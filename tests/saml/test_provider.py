from inge6 import constants
from inge6.saml.provider import Provider

def test_single_idp_files():
    provider = Provider()

    provider.sp_metadata
    provider.get_idp_metadata(constants.IdPName.DIGID)