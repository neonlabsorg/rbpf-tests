pub use solana_rbpf::{
    aligned_memory::AlignedMemory,
    ebpf,
    elf::Executable,
    memory_region::{MemoryMapping, MemoryRegion},
    program::{BuiltinProgram, FunctionRegistry},
    verifier::RequisiteVerifier,
    vm::{TestContextObject},
};

use std::{env, fs, sync::Arc};
use solana_rbpf::error::StableResult;
use solana_rbpf::jit::JitCompiler;
use solana_rbpf::vm::Config;

fn main() {
    let args: Vec<String> = env::args().collect();
    let so_path = "dumped_program.so";

    let so_bytes = match fs::read(so_path) {
        Ok(bytes) => bytes,
        Err(err) => {
            eprintln!("Failed to read the .so file: {}", err);
            return;
        }
    };

    // Create a Config object
    let config = Config {
        enable_instruction_meter: true,
        max_call_depth: 64,
        ..Config::default()
    };

    // Create a FunctionRegistry with the correct type signature
    let function_registry = FunctionRegistry::<for<'a> fn(*mut TestContextObject, u64, u64, u64, u64, u64)>::default();

    // Create the loader with the proper function registry
    let loader = Arc::new(BuiltinProgram::new_loader(config, function_registry));

    let executable = match Executable::<TestContextObject>::from_elf(
        &so_bytes,
        loader.clone(),
    ) {
        Ok(mut exe) => {
            if let Err(err) = exe.verify::<RequisiteVerifier>() {
                eprintln!("Verification failed: {}", err);
                return;
            }
            exe
        }
        Err(err) => {
            eprintln!("Failed to create executable: {}", err);
            return;
        }
    };

    let sbpf_version = executable.get_sbpf_version();
    let config = executable.get_config();

    let mut stack = AlignedMemory::<{ ebpf::HOST_ALIGN }>::zero_filled(config.stack_size());
    let stack_len = stack.len();
    let mut heap = AlignedMemory::<{ ebpf::HOST_ALIGN }>::with_capacity(128); // Example heap size

    let mut mem = AlignedMemory::<{ ebpf::HOST_ALIGN }>::zero_filled(128); // Adjust size as needed

    let regions = vec![
        executable.get_ro_region(),
        MemoryRegion::new_writable(stack.as_slice_mut(), ebpf::MM_STACK_START),
        MemoryRegion::new_writable(heap.as_slice_mut(), ebpf::MM_HEAP_START),
        MemoryRegion::new_writable(mem.as_slice_mut(), ebpf::MM_INPUT_START),
    ];

    let memory_mapping = match MemoryMapping::new(regions, config, sbpf_version) {
        Ok(mapping) => mapping,
        Err(err) => {
            eprintln!("Failed to create memory mapping: {}", err);
            return;
        }
    };

    // Compile the program using JIT
    let mut jit_compiler = match JitCompiler::new(&executable) {
        Ok(jit) => jit,
        Err(err) => {
            eprintln!("Failed to create JIT compiler: {}", err);
            return;
        }
    };

    let compiled_program = match jit_compiler.compile() {
        Ok(prog) => prog,
        Err(err) => {
            eprintln!("JIT compilation failed: {}", err);
            return;
        }
    };

    // Execute the JIT-compiled program
    let mut context_object = TestContextObject::new(10_000); // Increased CUs limit
    let (instruction_count, result) = compiled_program.execute_program(
        &memory_mapping,
        &mut context_object,
        true,
    );

    match result {
        StableResult::Ok(exit_code) => {
            println!("Program executed successfully!");
            println!("Exit code: {}", exit_code);
            println!("Instruction count: {}", instruction_count);
        }
        StableResult::Err(err) => {
            eprintln!("Program execution failed: {}", err);
        }
    }
}
