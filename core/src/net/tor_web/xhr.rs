//! A synchronous request from the browser. Only a worker may block on one, which is where the
//! wallet runs, and blocking there is what lets the core keep its synchronous transport. The
//! request carries no cookie or credential, and the page's Content Security Policy limits it to
//! the endpoints the release lists.

use web_sys::XmlHttpRequest;

/// The status and body of one request, or none when the browser refused or could not reach it.
pub(super) fn request(method: &str, url: &str, body: Option<&str>) -> Option<(u16, String)> {
    let xhr = XmlHttpRequest::new().ok()?;
    xhr.open_with_async(method, url, false).ok()?;
    if body.is_some() {
        xhr.set_request_header("Content-Type", "application/json").ok()?;
    }
    xhr.send_with_opt_str(body).ok()?;
    let status = xhr.status().ok()?;
    // A status of 0 is a request the browser blocked or could not make, which is not a reply.
    if status == 0 {
        return None;
    }
    Some((status, xhr.response_text().ok()??))
}
