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

#[test]
fn limits_vs_fixed_regs() {
    use crate::fuzzing::func::{InstData, InstOpcode};
    use crate::ion::Ctx;
    use crate::{Operand, PReg, RegClass, VReg};
    use alloc::vec;

    let mut builder = func::FuncBuilder::new();
    let v0i = builder.add_vreg(RegClass::Int);
    let p35i = PReg::new(35, RegClass::Int);
    let block0 = builder.add_block();
    builder.add_inst(
        block0,
        InstData {
            op: InstOpcode::Op,
            operands: vec![Operand::reg_def(v0i)],
            clobbers: vec![],
        },
    );
    builder.add_inst(block0, InstData::ret());
    builder.compute_doms();
    let func = builder.finalize();
    println!("func: {func:#?}");

    let env = func::machine_env();
    let mut ctx = Ctx::default();
    ion::run(&func, &env, &mut ctx, false, false).expect("regalloc failed");
}
