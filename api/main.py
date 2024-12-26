import os
import logging
import requests
from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt, jwk
from jose.utils import base64url_decode

logger = logging.getLogger("api_logger")
app = FastAPI()

@app.on_event("startup")
def configure_logging():
    logging.basicConfig(level=logging.DEBUG)
    logger.info("API started. Logging configured.")


KEYCLOAK_URL = os.getenv("KEYCLOAK_URL")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM")
OIDC_DISCOVERY_URL = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/.well-known/openid-configuration"
ALGORITHM = "RS256"

# Кэш: словарь, где ключ = kid, значение = jwk-объект
JWKS_CACHE = {}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def load_jwks():
    """
    Загружает JWKS из Keycloak и возвращает список ключей.
    """
    logger.debug("Loading JWKS from Keycloak...")
    oidc_config = requests.get(OIDC_DISCOVERY_URL).json()
    jwks_uri = oidc_config["jwks_uri"]
    logger.debug(f"jwks_uri from OIDC config: {jwks_uri}")

    jwks = requests.get(jwks_uri).json()
    keys = jwks.get("keys", [])
    if not keys:
        logger.error("No keys found in JWKS")
        raise HTTPException(status_code=500, detail="No keys found in JWKS")
    return keys

def get_jwk_for_kid(kid: str):
    """
    Ищет jwk-ключ в кэше или загружает JWKS из Keycloak и находит ключ по kid.
    """
    if kid in JWKS_CACHE:
        # Если у нас есть закэшированный jwk для этого kid, берём его
        return JWKS_CACHE[kid]

    # Иначе загружаем заново JWKS
    keys = load_jwks()

    # Ищем ключ, где kid совпадает
    for key_data in keys:
        if key_data.get("kid") == kid:
            # Найден нужный ключ
            logger.debug(f"Matched kid={kid} in JWKS.")
            jwk_obj = jwk.construct(key_data, ALGORITHM)
            JWKS_CACHE[kid] = jwk_obj  # Сохраним в кэш
            return jwk_obj

    logger.error(f"No matching kid '{kid}' found in JWKS.")
    raise HTTPException(status_code=401, detail=f"No matching kid '{kid}' found in JWKS")

def validate_token(authorization: str = Header(None)):
    logger.debug(f"Authorization header: {authorization}")
    if not authorization:
        logger.warning("Missing token.")
        raise HTTPException(status_code=401, detail="Missing token")

    try:
        token = authorization.split(" ")[1]
        logger.debug(f"Received token: {token}")

        # 1. Сначала парсим только header, чтобы узнать kid
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        logger.debug(f"Token header: {header}")

        if not kid:
            logger.error("No 'kid' found in token header.")
            raise HTTPException(status_code=401, detail="No kid in token header")

        # 2. Получаем jwk-ключ из кэша/Keycloak для соответствующего kid
        public_jwk = get_jwk_for_kid(kid)

        # 3. Теперь полноценно декодируем и проверяем подпись
        payload = jwt.decode(token, public_jwk, algorithms=[ALGORITHM])
        logger.debug(f"Token payload: {payload}")

        # 4. Проверяем наличие роли
        roles = payload.get("realm_access", {}).get("roles", [])
        logger.debug(f"User roles from token: {roles}")
        if "prothetic_user" not in roles:
            logger.warning(f"User does not have 'prothetic_user' role. Roles: {roles}")
            raise HTTPException(status_code=403, detail="Forbidden: insufficient role")

    except jwt.ExpiredSignatureError as e:
        logger.error(f"Token expired: {e}")
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.JWTError as e:
        logger.error(f"Invalid token: {e}")
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        logger.exception(f"Unexpected error: {str(e)}")
        raise HTTPException(status_code=401, detail="Unexpected validation error")

    return payload

@app.get("/reports")
def get_reports(user=Depends(validate_token)):
    logger.info(f"Serving /reports for user payload: {user}")
    return {
        "data": [
            {"id": 1, "report": "report"}
        ]
    }
