//! Port forwarding control via ControlMaster sessions.

use crate::Result;

/// List active port forwards on a ControlMaster session.
pub async fn list_forwards(_control_path: &std::path::Path) -> Result<()> {
    todo!()
}

/// Cancel a port forward on a ControlMaster session.
pub async fn cancel_forward(_control_path: &std::path::Path, _local_port: u16) -> Result<()> {
    todo!()
}
