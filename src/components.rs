use crate::tasks::Task;

pub struct Director {
    tasks: Vec<Box<dyn Task>>
}
