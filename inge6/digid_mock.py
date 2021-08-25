import uuid

from fastapi.responses import RedirectResponse, HTMLResponse

from .models import DigiDMockRequest, DigiDMockCatchRequest

def digid_mock(digid_mock_request: DigiDMockRequest) -> HTMLResponse:
    state = digid_mock_request.state
    authorize_request = digid_mock_request.authorize_request
    idp_name = digid_mock_request.idp_name
    relay_state = digid_mock_request.RelayState
    artifact = str(uuid.uuid4())
    http_content = f"""
    <html>
    <h1> DigiD MOCK </h1>
    <div style='font-size:36;'>
        <form method="POST" action="/digid-mock-catch">
            <label style='height:200px; width:400px' for="bsn">BSN Value:</label><br>
            <input id='bsn_inp' style='height:200px; width:400px; font-size:36pt' type="text" id="bsn" value="999991772" name="bsn"><br>
            <input type="hidden" name="SAMLart" value="{artifact}">
            <input type="hidden" name="RelayState" value="{relay_state}">
        </form>
    </div>
    <a href='' id="submit_two" relayState="{relay_state}" samlArt="{artifact}" style='font-size:55; color: white; background-color:grey; display:box'> Login / Submit </a>
    <br />
    <a href='/login-digid?force_digid=1&state={state}&idp_name={idp_name}&authorize_request={authorize_request}' style='font-size:55; background-color:purple; display:box'>Actual DigiD</a>
    <script>
        window.onload = function funLoad() {{
            bsn_input_listener()
            document.getElementById('bsn_inp').onchange = bsn_input_listener
        }}

        function bsn_input_listener() {{
            submitButton = document.getElementById("submit_two")
            relayState = submitButton.getAttribute("relaystate")
            bsn = document.getElementById("bsn_inp").value
            samlArt = submitButton.getAttribute("samlart")
            href = '/digid-mock-catch?bsn=' + bsn + '&SAMLart=' + samlArt + '&RelayState=' + relayState
            submitButton.href = href
        }}
    </script>
    </html>
    """
    return HTMLResponse(content=http_content, status_code=200)


def digid_mock_catch(request: DigiDMockCatchRequest) -> RedirectResponse:
    bsn = request.bsn
    relay_state = request.RelayState

    response_uri = '/acs' + f'?SAMLart={bsn}&RelayState={relay_state}&mocking=1'
    return RedirectResponse(response_uri, status_code=303)
