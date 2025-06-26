/**
 * Handles form submission for the mock page by intercepting the submit event.
 * Redirects the browser to the form's action URL with all form input values as query parameters.
 *
 * This approach is used to work around the Content Security Policy (CSP) 'form-action' restriction,
 * submit works but the catch route redirects to the acs endpoint and the acs endpoint redirects to the client.
 * The CSP policy blocks the redirect to the client application.
 *
 * Read more about the CSP 'form-action' directive here:
 * https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/form-action1
 *
 * Since this workaround is only needed for the mock page and not needed in production,
 * it is unnecessary to loosen CSP rules by adding, for example, 'https:' to the policy.
 * DigiD does use 'https:' in their own form-action policy, but for us it is not needed.
 */
window.onload = function() {
    const form = document.querySelector('form');
    if (form) {
        form.addEventListener('submit', mock_form_submit_listener);
    }
}

function mock_form_submit_listener(e) {
    e.preventDefault();
    const form = e.target;
    const params = Array.from(form.elements)
        .filter(el => el.name && !el.disabled)
        .map(el => encodeURIComponent(el.name) + '=' + encodeURIComponent(el.value))
        .join('&');
    const action = form.getAttribute('action');
    window.location.href = action + (action.includes('?') ? '&' : '?') + params;
}