from fastapi import FastAPI

import models  # noqa: F401
from auth import router as auth_router
from database import Base, engine

Base.metadata.create_all(bind=engine)

app = FastAPI(title="AIDataCheck")
app.include_router(auth_router)