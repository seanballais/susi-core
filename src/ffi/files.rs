/// Returns the value in a Result, or causes the function to return `ret_val`.
macro_rules! open_file_or_return_on_err {
    ($result: expr, $path: expr, $err_val: expr) => {
        match $result {
            Ok(f) => f,
            Err(e) => {
                update_last_error(e);
                return $err_val;
            }
        }
    };
}

pub(crate) use open_file_or_return_on_err;
