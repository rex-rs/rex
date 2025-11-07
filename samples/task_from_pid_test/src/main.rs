#![no_std]
#![no_main]

extern crate rex;

use rex::tracepoint::*;
use rex::task_struct::{TaskStruct, TaskStructOwned};
use rex::{Result, rex_printk, rex_tracepoint};

#[rex_tracepoint]
fn rex_prog_task_from_pid_test(
    obj: &tracepoint<SyscallsEnterDupCtx>,
    _: &'static SyscallsEnterDupCtx,
) -> Result {
    let current_task_opt = obj.bpf_get_current_task();
    if let Some(current_task) = current_task_opt {
        let current_pid = current_task.get_pid();
        rex_printk!("Current task PID: {}\n", current_pid)?;

        // Test TaskStruct::from_pid - look up current task by PID
        if let Some(task_from_pid) = TaskStruct::from_pid(current_pid) {
            let found_pid = task_from_pid.get_pid();
            let found_tgid = task_from_pid.get_tgid();

            if let Ok(comm) = task_from_pid.get_comm() {
                rex_printk!("Found task via PID {}: TGID={}, comm={:?}\n",
                           found_pid, found_tgid, comm)?;
            } else {
                rex_printk!("Found task via PID {}: TGID={}\n",
                           found_pid, found_tgid)?;
            }

            // Test cloning a reference
            if let Some(cloned_task) = task_from_pid.clone_ref() {
                rex_printk!("Successfully cloned task reference\n")?;
                let cloned_pid = cloned_task.get_pid();
                rex_printk!("Cloned task PID: {}\n", cloned_pid)?;
                // cloned_task will be automatically released when it goes out of scope
            }

            // task_from_pid will be automatically released when it goes out of scope
        } else {
            rex_printk!("Failed to find task with PID {}\n", current_pid)?;
        }

        // Test TaskStruct::acquire_current
        if let Some(acquired_current) = TaskStruct::acquire_current() {
            rex_printk!("Successfully acquired current task reference\n")?;
            let acquired_pid = acquired_current.get_pid();
            rex_printk!("Acquired current task PID: {}\n", acquired_pid)?;
            // acquired_current will be automatically released when it goes out of scope
        } else {
            rex_printk!("Failed to acquire current task reference\n")?;
        }

        // Test looking up a non-existent PID
        if let Some(_task) = TaskStruct::from_pid(99999) {
            rex_printk!("ERROR: Found non-existent PID 99999\n")?;
        } else {
            rex_printk!("Correctly returned None for non-existent PID 99999\n")?;
        }
    }

    Ok(0)
}