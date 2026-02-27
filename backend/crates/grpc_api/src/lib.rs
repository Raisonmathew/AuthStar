#![allow(non_snake_case)]
#![allow(unused_imports)]
#![allow(clippy::derive_partial_eq_without_eq)]

pub mod eiaa {
    #[allow(non_snake_case)]
    #[allow(non_camel_case_types)]
    pub mod runtime {
        tonic::include_proto!("eiaa.runtime");
    }
}
