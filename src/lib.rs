use nginx_rs::bindings::*;
use nginx_rs::core::*;
use nginx_rs::http::*;

use nginx_rs::{
    http_request_handler, ngx_modules, ngx_null_command
};

use std::os::raw::{c_char, c_void};
use std::ptr;

use chrono::prelude::*;

#[no_mangle]
static mut ngx_http_forbid_commands: [ngx_command_t; 1] = [ngx_null_command!()];

#[no_mangle]
static ngx_http_forbid_module_ctx: ngx_http_module_t = ngx_http_module_t {
    preconfiguration: Some(Module::preconfiguration),
    postconfiguration: Some(Module::postconfiguration),

    create_main_conf: Some(Module::create_main_conf),
    init_main_conf: Some(Module::init_main_conf),

    create_srv_conf: Some(Module::create_srv_conf),
    merge_srv_conf: Some(Module::merge_srv_conf),

    create_loc_conf: Some(Module::create_loc_conf),
    merge_loc_conf: Some(Module::merge_loc_conf),
};

#[no_mangle]
pub static mut ngx_http_forbid_module: ngx_module_t = ngx_module_t {
    ctx_index: ngx_uint_t::max_value(),
    index: ngx_uint_t::max_value(),
    name: ptr::null_mut(),
    spare0: 0,
    spare1: 0,
    version: nginx_version as ngx_uint_t,
    signature: NGX_RS_MODULE_SIGNATURE.as_ptr() as *const c_char,

    ctx: &ngx_http_forbid_module_ctx as *const _ as *mut _,
    commands: unsafe { &ngx_http_forbid_commands[0] as *const _ as *mut _ },
    type_: NGX_HTTP_MODULE as ngx_uint_t,

    init_master: None,
    init_module: None,
    init_process: None,
    init_thread: None,
    exit_thread: None,
    exit_process: None,
    exit_master: None,

    spare_hook0: 0,
    spare_hook1: 0,
    spare_hook2: 0,
    spare_hook3: 0,
    spare_hook4: 0,
    spare_hook5: 0,
    spare_hook6: 0,
    spare_hook7: 0,
};

ngx_modules!(ngx_http_forbid_module);

struct Module;

impl HTTPModule for Module {
    type MainConf = ();
    type SrvConf = ();
    type LocConf = LocConf;

    unsafe extern "C" fn postconfiguration(cf: *mut ngx_conf_t) -> ngx_int_t {
        let cmcf = ngx_http_conf_get_module_main_conf(cf, &ngx_http_core_module)
            as *mut ngx_http_core_main_conf_t;

        let h = ngx_array_push(
            &mut (*cmcf).phases[ngx_http_phases_NGX_HTTP_ACCESS_PHASE as usize].handlers,
        ) as *mut ngx_http_handler_pt;
        if h.is_null() {
            return ERROR.into();
        }

        *h = Some(ngx_http_forbid_access_handler);

        OK.into()
    }
}

#[derive(Default)]
struct LocConf {
    text: String,
}

impl Merge for LocConf {
    fn merge(&mut self, prev: &LocConf) {
        if self.text.is_empty() {
            self.text = String::from(if !prev.text.is_empty() {
                &prev.text
            } else {
                ""
            });
        }
    }
}

fn get_host(request: &mut Request) -> &NgxStr {
    let connection = request.connection();
    unsafe {
        let request_ptr = (*connection).data as *const ngx_http_request_t;
        return NgxStr::from_ngx_str((*((*request_ptr).headers_in.host)).value)
    }
}

http_request_handler!(ngx_http_forbid_access_handler, |request: &mut Request| {
    let now = Local::now();
    let now_str: String = now.format("%Y%m%d").to_string();
    let md5_res = md5::compute(now_str.as_bytes());
    let md5hex = format!("{:x}", md5_res);
    if let Ok(host) = get_host(request).to_str() {
        if host.contains("jellyfin") {
            if let Ok(user_agent) = request.user_agent().to_str() {
                if !user_agent.contains("JellyfinMediaPlayer")
                    || !user_agent.contains(&md5hex)
                {
                    return HTTP_FORBIDDEN.into();
                }
            }
        }
    }

    OK
});
