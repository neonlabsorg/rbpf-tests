use solana_rbpf::{
    aligned_memory::AlignedMemory,
    ebpf,
    elf::Executable,
    memory_region::{MemoryMapping, MemoryRegion},
    program::{BuiltinProgram, FunctionRegistry},
    verifier::RequisiteVerifier,
    vm::{EbpfVm, TestContextObject},
};
use std::{env, fs, sync::Arc};
use solana_rbpf::error::StableResult;
use solana_rbpf::vm::Config;

fn main() {
    let args: Vec<String> = env::args().collect();
    /*if args.len() < 2 {
        eprintln!("Usage: {} <path_to_program.so>", args[0]);
        return;
    }*/
    //let so_path = &args[1];
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
    let mut function_registry = FunctionRegistry::<for<'a> fn(*mut EbpfVm<'a, _>, u64, u64, u64, u64, u64)>::default();

    function_registry.register_function_hashed(b"sol_log_", my_sol_log_stub).unwrap();


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

    let mut context_object = TestContextObject::new(10_000); // Increased CUs limit
    let mut vm = EbpfVm::new(loader, sbpf_version, &mut context_object, memory_mapping, stack_len);

    let (instruction_count, result) = vm.execute_program(&executable, true);

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

fn my_sol_log_stub(
    vm_ptr: *mut EbpfVm<TestContextObject>,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
) {
    // Minimal example:
    // 1. We might want to get a reference to the VM or its config:
    let vm = unsafe { vm_ptr.as_mut() }.expect("VM pointer is null");
    // 2. We can do anything we like here (log, read memory, etc.)
    println!(
        "[my_sol_log_stub] Called with arguments: {}, {}, {}, {}, {}",
        arg1, arg2, arg3, arg4, arg5
    );

    // If you want to signal an error to the BPF code, set `vm.program_result = Err(...)`.
    // For a normal success, do nothing more.

    // Real Solana might read the string from BPF memory. For that, you'd do something like:
    // let memory = &mut vm.memory_mapping;
    // read some bytes from memory at arg1...
    // println!("log msg: {:?}", message);
}