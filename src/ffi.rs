// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
use crate::init_core_systems;

// We need to set `errors` to public visibility since it's used in `src/logging.rs`.
pub mod errors;
mod logging;
mod tasks;
mod verification;
mod files;

#[no_mangle]
pub extern "C" fn init_susi_core() {
    init_core_systems();

    tracing::info!("Finished initializing core systems");
}
