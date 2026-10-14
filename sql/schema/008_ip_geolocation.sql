-- Kaynak IP'lerin coğrafi konumu (DB-IP Lite, CC BY 4.0). Her IP bir kez çözülür.
CREATE TABLE IF NOT EXISTS ip_geolocation (
    ip           INET             PRIMARY KEY,
    -- false: özel ya da ayrılmış adres (ör. 10.x, belgeleme blokları); konumu yoktur.
    is_global    BOOLEAN          NOT NULL,
    country_code CHAR(2),
    country_name TEXT,
    city         TEXT,
    latitude     DOUBLE PRECISION,
    longitude    DOUBLE PRECISION,
    db_version   TEXT             NOT NULL,
    looked_up_at TIMESTAMPTZ      NOT NULL DEFAULT now()
);
