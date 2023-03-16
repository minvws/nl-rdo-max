from typing import Union
import uvicorn

from fastapi import FastAPI
from fastapi import APIRouter, Request, Response
from fastapi.middleware.cors import CORSMiddleware
import requests


app = FastAPI()
origins = [
    "https://poc-1.uzi.bavod.nl",
    "http://localhost:8000"
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

base_dest = "http://localhost:8088"


@app.get("/{full_path:path}")
async def catch_all(request: Request, full_path: str):
    response = requests.get(
        f"{base_dest}/{full_path}",
        headers=request.headers
    )
    return Response(
        content=response.content,
        headers=response.headers
    )


if __name__ == "__main__":
    kwargs = {
        "host": "0.0.0.0",
        "port": 8444,
        "reload": True,
        "proxy_headers": True,
        "workers": 1,
        "ssl_keyfile": "secrets/ssl/server.key",
        "ssl_certfile": "secrets/ssl/server.crt"
    }
    uvicorn.run(
        "tools.ssl-redirect:app",
        **kwargs)
