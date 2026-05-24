use std::rc::Rc;

pub type PlatformHostRef = Rc<dyn PlatformHost>;

pub trait PlatformHost {
    fn handle_platform_action(&self, api: &str, source_name: &str, args_json: &str) -> String;
}
