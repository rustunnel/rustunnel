use std::alloc::System;

#[global_allocator]
static GLOBAL_ALLOCATOR: System = System;
