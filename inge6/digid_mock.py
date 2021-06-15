import uuid

from fastapi import Request
from fastapi.responses import RedirectResponse, HTMLResponse

async def digid_mock(request: Request) -> HTMLResponse:
    body = await request.form()
    state = request.query_params['state']
    relay_state = body['RelayState']
    artifact = str(uuid.uuid4())
    http_content = f"""
    <html>
    <h1> DigiD MOCK </h1>
    <div style='font-size:36;'>
        <form method="POST" action="/digid-mock-catch">
            <label style='height:200px; width:400px' for="bsn">BSN Value:</label><br>
            <input id='bsn_inp' style='height:200px; width:400px; font-size:36pt' type="text" id="bsn" value="900212640" name="bsn"><br>
            <input type="hidden" name="SAMLart" value="{artifact}">
            <input type="hidden" name="RelayState" value="{relay_state}">
        </form>
    </div>
    <a href='' id="submit_two" relayState={relay_state} samlArt={artifact} style='font-size:55; color: white; background-color:grey; display:box'> Login / Submit </a>
    <br />
    <a href='/login-digid?force_digid=1&state={state}' style='font-size:55; background-color:purple; display:box'>Actual DigiD</a>
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


async def digid_mock_catch(request: Request) -> RedirectResponse:
    bsn = request.query_params['bsn']
    relay_state = request.query_params['RelayState']

    response_uri = '/acs' + f'?SAMLart={bsn}&RelayState={relay_state}&mocking=1'
    return RedirectResponse(response_uri, status_code=303)
