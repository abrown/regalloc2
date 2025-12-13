//! Fuzz the `ion` register allocator.

use crate::serialize::SerializableFunction;
use crate::{checker, fuzzing::func, ion};
use arbitrary::{Arbitrary, Result, Unstructured};
use core::cell::RefCell;
use std::thread_local;

/// `ion`-specific options for generating functions.
const OPTIONS: func::Options = func::Options {
    reused_inputs: true,
    fixed_regs: true,
    fixed_nonallocatable: true,
    clobbers: true,
    reftypes: true,
    callsite_ish_constraints: true,
    limit_constraints: true,
    ..func::Options::DEFAULT
};

/// A convenience wrapper to generate a [`func::Func`] with `ion`-specific
/// options enabled.
#[derive(Clone, Debug)]
pub struct TestCase {
    func: func::Func,
    annotate: bool,
    check_ssa: bool,
}

impl Arbitrary<'_> for TestCase {
    fn arbitrary(u: &mut Unstructured) -> Result<TestCase> {
        let func = func::Func::arbitrary_with_options(u, &OPTIONS)?;
        let annotate = bool::arbitrary(u)?;
        let check_ssa = bool::arbitrary(u)?;
        Ok(TestCase {
            func,
            annotate,
            check_ssa,
        })
    }
}

/// Test a single function with the `ion` allocator.
///
/// This also:
/// - optionally creates annotations
/// - optionally verifies the incoming SSA
/// - runs the [`checker`].
pub fn check(t: TestCase) {
    let TestCase {
        func,
        annotate,
        check_ssa,
    } = &t;
    log::trace!("func:\n{func:?}");

    let env = func::machine_env();
    thread_local! {
        // We test that ctx is cleared properly between runs.
        static CTX: RefCell<ion::Ctx> = RefCell::default();
    }

    CTX.with(|ctx| {
        if let Err(e) = ion::run(func, &env, &mut *ctx.borrow_mut(), *annotate, *check_ssa) {
            let serializable = SerializableFunction::new(func, env.clone());
            let bytes = bincode::serialize(&serializable).expect("could not serialize function");
            std::fs::write("fuzz-input.bin", &bytes).expect("unable to write to file");
            panic!("regalloc failed: {}", e);
        }

        let mut checker = checker::Checker::new(func, &env);
        checker.prepare(&ctx.borrow().output);
        checker.run().expect("checker failed");
    });
}

#[test]
fn smoke() {
    arbtest::arbtest(|u| {
        let test_case = TestCase::arbitrary(u)?;
        check(test_case);
        Ok(())
    })
    .budget_ms(1_000);
}

/// This test demonstrates that moves between fixed registers and limited
/// registers work as expected. Even though `v0i` is constrained to `p35i`
/// __AND__ the fully-subscribed range `0..=1`, the proper copies are inserted
/// and the test case allocates.
#[test]
fn limits_vs_fixed_regs() {
    use crate::fuzzing::func::{InstData, InstOpcode};
    use crate::ion::Ctx;
    use crate::{Operand, PReg, RegClass};
    use alloc::vec;

    fn inst(operands: &[Operand]) -> InstData {
        InstData {
            op: InstOpcode::Op,
            operands: operands.to_vec(),
            clobbers: vec![],
        }
    }

    let _ = env_logger::try_init();

    let mut builder = func::FuncBuilder::new();
    let v0i = builder.add_vreg(RegClass::Int);
    let v1i = builder.add_vreg(RegClass::Int);
    let v2i = builder.add_vreg(RegClass::Int);
    let p35i = PReg::new(35, RegClass::Int);
    let block0 = builder.add_block();
    // inst0(Def: v0i reg, Def: v1i reg, Def: v2i reg)
    builder.add_inst(
        block0,
        inst(&[
            Operand::reg_def(v0i),
            Operand::reg_def(v1i),
            Operand::reg_def(v2i),
        ]),
    );
    // inst1(Use: v0i fixed(p35i))
    builder.add_inst(block0, inst(&[Operand::reg_fixed_use(v0i, p35i)]));
    // inst2(Use: v0i limit(0..=1), Use: v1i limit(0..=1), Use: v2i)
    builder.add_inst(
        block0,
        inst(&[
            Operand::reg_limited_use(v0i, 2),
            Operand::reg_limited_use(v1i, 2),
            Operand::reg_use(v2i),
        ]),
    );
    // inst3(ret)
    builder.add_inst(block0, InstData::ret());
    builder.compute_doms();
    let func = builder.finalize();
    log::trace!("{func:?}");

    let env = func::machine_env();
    let mut ctx = Ctx::default();
    ion::run(&func, &env, &mut ctx, false, false).expect("regalloc failed");
}

/// This test checks what happens when we overuse limits in a single
/// instruction.
#[test]
fn oversubscribed_limits() {
    use crate::fuzzing::func::{InstData, InstOpcode};
    use crate::ion::Ctx;
    use crate::{Operand, RegClass};
    use alloc::vec;

    fn inst(operands: &[Operand]) -> InstData {
        InstData {
            op: InstOpcode::Op,
            operands: operands.to_vec(),
            clobbers: vec![],
        }
    }

    let _ = env_logger::try_init();

    let mut builder = func::FuncBuilder::new();
    let v0i = builder.add_vreg(RegClass::Int);
    let v1i = builder.add_vreg(RegClass::Int);
    let block0 = builder.add_block();
    // inst0(Def: v0i reg)
    builder.add_inst(block0, inst(&[Operand::reg_def(v0i)]));
    // inst1(Def: v1i limit(0..=1), Use: v0i limit(0..=1), Use: v0i limit(0..=1), Use: v0i limit(0..=1), Use: v0i limit(0..=3))
    builder.add_inst(
        block0,
        inst(&[
            Operand::reg_limited_def(v1i, 2),
            Operand::reg_limited_use(v0i, 2),
            Operand::reg_limited_use(v0i, 2),
            Operand::reg_limited_use(v0i, 2),
            Operand::reg_limited_use(v0i, 4),
        ]),
    );
    // inst2(Use: v1i limit(0..=1), Use: v0i limit(0..=1))
    builder.add_inst(
        block0,
        inst(&[
            Operand::reg_limited_use(v1i, 2),
            Operand::reg_limited_use(v0i, 2),
        ]),
    );
    // inst3(ret)
    builder.add_inst(block0, InstData::ret());
    builder.compute_doms();
    let func = builder.finalize();
    log::trace!("{func:?}");

    let env = func::machine_env();
    let mut ctx = Ctx::default();
    ion::run(&func, &env, &mut ctx, false, false).expect("regalloc failed");
}

/// This test checks that a limit-constrained register can be moved to a fixed
/// register.
#[test]
fn move_limited_to_fixed() {
    use crate::fuzzing::func::{InstData, InstOpcode};
    use crate::ion::Ctx;
    use crate::{Operand, PReg, RegClass};
    use alloc::vec;

    fn inst(operands: &[Operand]) -> InstData {
        InstData {
            op: InstOpcode::Op,
            operands: operands.to_vec(),
            clobbers: vec![],
        }
    }

    let _ = env_logger::try_init();

    let mut builder = func::FuncBuilder::new();
    let v0i = builder.add_vreg(RegClass::Int);
    let v1i = builder.add_vreg(RegClass::Int);
    let v2i = builder.add_vreg(RegClass::Int);
    let p35i = PReg::new(35, RegClass::Int);
    let block0 = builder.add_block();
    // inst0(Def: v0i reg)
    builder.add_inst(block0, inst(&[Operand::reg_def(v0i)]));
    // inst1(Def: v1i limit(0..=1), Def: v2i limit(0..=1))
    builder.add_inst(
        block0,
        inst(&[
            Operand::reg_limited_def(v1i, 2),
            Operand::reg_limited_def(v2i, 2),
        ]),
    );
    // inst2(Use: v0i limit(0..=1))
    builder.add_inst(block0, inst(&[Operand::reg_limited_use(v0i, 2)]));
    // inst3(Use: v0i fixed(p35i))
    builder.add_inst(block0, inst(&[Operand::reg_fixed_use(v0i, p35i)]));
    // inst4(Use: v1i limit(0..=1), Use: v2i limit(0..=1)
    builder.add_inst(
        block0,
        inst(&[
            Operand::reg_limited_use(v1i, 2),
            Operand::reg_limited_use(v2i, 2),
        ]),
    );
    // inst5(ret)
    builder.add_inst(block0, InstData::ret());
    builder.compute_doms();
    let func = builder.finalize();
    log::trace!("{func:?}");

    let env = func::machine_env();
    let mut ctx = Ctx::default();
    ion::run(&func, &env, &mut ctx, false, false).expect("regalloc failed");
}

/// This test checks that a limit-constrained register can be moved to a fixed
/// register.
#[test]
fn multi_use() {
    use crate::fuzzing::func::{InstData, InstOpcode};
    use crate::ion::Ctx;
    use crate::{Operand, PReg, RegClass};
    use alloc::vec;

    fn inst(operands: &[Operand]) -> InstData {
        InstData {
            op: InstOpcode::Op,
            operands: operands.to_vec(),
            clobbers: vec![],
        }
    }

    let _ = env_logger::try_init();

    let mut builder = func::FuncBuilder::new();
    let v0i = builder.add_vreg(RegClass::Int);
    let p35i = PReg::new(10, RegClass::Int);
    let block0 = builder.add_block();
    // inst0(Def: v0i reg)
    builder.add_inst(block0, inst(&[Operand::reg_def(v0i)]));
    // inst1(Use: v0i limit(0..=1), Use: v0i limit(0..=1))
    builder.add_inst(
        block0,
        inst(&[
            Operand::reg_limited_use(v0i, 2),
            Operand::reg_limited_use(v0i, 2),
            Operand::reg_limited_use(v0i, 2),
        ]),
    );
    // inst1(Use: v0i reg, Use: v0i any)
    builder.add_inst(
        block0,
        inst(&[Operand::reg_use(v0i), Operand::reg_fixed_use(v0i, p35i)]),
    );
    // inst...(ret)
    builder.add_inst(block0, InstData::ret());
    builder.compute_doms();
    let func = builder.finalize();
    log::trace!("{func:?}");

    let env = func::machine_env();
    let mut ctx = Ctx::default();
    ion::run(&func, &env, &mut ctx, false, false).expect("regalloc failed");
}

/// Rahul's fuzz test case.
#[test]
fn complex_constraints() {
    use crate::fuzzing::func::{InstData, InstOpcode};
    use crate::ion::Ctx;
    use crate::{Operand, OperandConstraint, OperandKind, OperandPos, PReg, RegClass};
    use alloc::vec;

    fn inst(operands: &[Operand]) -> InstData {
        InstData {
            op: InstOpcode::Op,
            operands: operands.to_vec(),
            clobbers: vec![],
        }
    }

    let _ = env_logger::try_init();

    let mut builder = func::FuncBuilder::new();
    let v0i = builder.add_vreg(RegClass::Int);
    let v1i = builder.add_vreg(RegClass::Int);
    let v2i = builder.add_vreg(RegClass::Int);
    let v3i = builder.add_vreg(RegClass::Int);
    let v4i = builder.add_vreg(RegClass::Int);
    let v5v = builder.add_vreg(RegClass::Vector);
    let v6i = builder.add_vreg(RegClass::Int);
    let v7v = builder.add_vreg(RegClass::Vector);
    let v8v = builder.add_vreg(RegClass::Vector);
    let v9i = builder.add_vreg(RegClass::Int);
    let v10f = builder.add_vreg(RegClass::Float);
    let v11f = builder.add_vreg(RegClass::Float);

    let p26i = PReg::new(26, RegClass::Int);
    let p58i = PReg::new(58, RegClass::Int);
    let p27i = PReg::new(27, RegClass::Int);
    let p39i = PReg::new(39, RegClass::Int);
    let p9i = PReg::new(9, RegClass::Int);
    let p3i = PReg::new(3, RegClass::Int);

    let block0 = builder.add_block();

    // inst0: Op ops:[Def@Early: v0i limit(0..=7)]
    builder.add_inst(
        block0,
        inst(&[Operand::new(
            v0i,
            OperandConstraint::Limit(8),
            OperandKind::Def,
            OperandPos::Early,
        )]),
    );

    // inst1: Op ops:[Def: v1i fixed(p26i), Use: v0i any, Use: v0i fixed(p58i), Use: v0i fixed(p27i),
    //                Use: v0i any, Use: v0i fixed(p39i), Use: v0i any, Use: v0i fixed(p26i)]
    builder.add_inst(
        block0,
        inst(&[
            Operand::reg_fixed_def(v1i, p26i),
            Operand::any_use(v0i),
            Operand::reg_fixed_use(v0i, p58i),
            Operand::reg_fixed_use(v0i, p27i),
            Operand::any_use(v0i),
            Operand::reg_fixed_use(v0i, p39i),
            Operand::any_use(v0i),
            Operand::reg_fixed_use(v0i, p26i),
        ]),
    );

    // inst2: Op ops:[Def@Early: v2i limit(0..=7), Use: v0i limit(0..=7), Use: v0i limit(0..=7),
    //                Use: v0i limit(0..=7), Use: v0i limit(0..=7), Use: v0i limit(0..=7),
    //                Use: v0i limit(0..=7), Use: v0i limit(0..=7), Use: v1i limit(0..=15),
    //                Use: v0i limit(0..=15)]
    builder.add_inst(
        block0,
        inst(&[
            Operand::new(
                v2i,
                OperandConstraint::Limit(8),
                OperandKind::Def,
                OperandPos::Early,
            ),
            Operand::reg_limited_use(v0i, 8),
            Operand::reg_limited_use(v0i, 8),
            Operand::reg_limited_use(v0i, 8),
            Operand::reg_limited_use(v0i, 8),
            Operand::reg_limited_use(v0i, 8),
            Operand::reg_limited_use(v0i, 8),
            Operand::reg_limited_use(v0i, 8),
            Operand::reg_limited_use(v1i, 16),
            Operand::reg_limited_use(v0i, 16),
        ]),
    );

    // inst3: Op ops:[Def@Early: v3i any]
    builder.add_inst(
        block0,
        inst(&[Operand::new(
            v3i,
            OperandConstraint::Any,
            OperandKind::Def,
            OperandPos::Early,
        )]),
    );

    // inst4: Op ops:[Def@Early: v4i fixed(p9i), Use: v3i any, Use: v3i any, Use: v3i any,
    //                Use: v0i any, Use: v0i fixed(p3i), Use: v3i any, Use: v3i any, Use: v3i any,
    //                Use: v3i limit(0..=15), Def: v5v any, Def: v6i any, Def: v7v any,
    //                Def: v8v any, Def: v9i any, Def: v10f any, Def: v11f any]
    builder.add_inst(
        block0,
        inst(&[
            Operand::new(
                v4i,
                OperandConstraint::FixedReg(p9i),
                OperandKind::Def,
                OperandPos::Early,
            ),
            Operand::any_use(v3i),
            Operand::any_use(v3i),
            Operand::any_use(v3i),
            Operand::any_use(v0i),
            Operand::reg_fixed_use(v0i, p3i),
            Operand::any_use(v3i),
            Operand::any_use(v3i),
            Operand::any_use(v3i),
            Operand::reg_limited_use(v3i, 16),
            Operand::any_def(v5v),
            Operand::any_def(v6i),
            Operand::any_def(v7v),
            Operand::any_def(v8v),
            Operand::any_def(v9i),
            Operand::any_def(v10f),
            Operand::any_def(v11f),
        ]),
    );

    // inst5: Ret
    builder.add_inst(block0, InstData::ret());

    builder.compute_doms();
    let func = builder.finalize();
    log::trace!("{func:?}");

    let env = func::machine_env();
    let mut ctx = Ctx::default();
    ion::run(&func, &env, &mut ctx, false, false).expect("regalloc failed");
}

/// This is a minimization of `complex_constraints` that continues to fail with
/// `TooManyLiveRegs`.
#[test]
fn complex_constraints_minimized() {
    use crate::fuzzing::func::{InstData, InstOpcode};
    use crate::ion::Ctx;
    use crate::{Operand, PReg, RegClass};
    use alloc::vec;

    fn inst(operands: &[Operand]) -> InstData {
        InstData {
            op: InstOpcode::Op,
            operands: operands.to_vec(),
            clobbers: vec![],
        }
    }

    let _ = env_logger::try_init();

    let mut builder = func::FuncBuilder::new();
    let v0i = builder.add_vreg(RegClass::Int);
    let v1i = builder.add_vreg(RegClass::Int);
    let v2i = builder.add_vreg(RegClass::Int);
    let v3i = builder.add_vreg(RegClass::Int);

    let p25i = PReg::new(25, RegClass::Int);
    let p26i = PReg::new(26, RegClass::Int);
    let p27i = PReg::new(27, RegClass::Int);
    let p28i = PReg::new(28, RegClass::Int);

    let block0 = builder.add_block();

    // inst0:
    builder.add_inst(block0, inst(&[Operand::reg_limited_def(v0i, 4)]));

    // inst1:
    builder.add_inst(
        block0,
        inst(&[
            Operand::reg_fixed_def(v1i, p25i),
            Operand::reg_fixed_use(v0i, p26i),
            Operand::reg_fixed_use(v0i, p27i),
        ]),
    );

    // inst2:
    builder.add_inst(
        block0,
        inst(&[
            Operand::reg_def(v2i),
            Operand::reg_limited_use(v0i, 2),
            Operand::reg_limited_use(v0i, 2),
            Operand::reg_limited_use(v1i, 8),
        ]),
    );

    // inst3:
    builder.add_inst(
        block0,
        inst(&[
            Operand::reg_def(v3i),
            Operand::reg_fixed_use(v0i, p28i),
            Operand::any_use(v0i),
        ]),
    );

    // inst4: Ret
    builder.add_inst(block0, InstData::ret());

    builder.compute_doms();
    let func = builder.finalize();
    log::trace!("{func:?}");

    let env = func::machine_env();
    let mut ctx = Ctx::default();
    ion::run(&func, &env, &mut ctx, false, false).expect("regalloc failed");
}
