from pydantic import BaseModel, HttpUrl


class URLCheckRequest(BaseModel):
    url: HttpUrl