from fastapi import FastAPI

digid_mock_app = FastAPI()
digid_mock_app.routes.append(digid_router)

@pytest.fixture
def digid_mocked_router()
    TestClient(digid_mock_app)
