-- Bases de datos separadas por modo: la app vulnerable y la endurecida no
-- comparten estado, así las evidencias "antes/después" no se contaminan.
CREATE DATABASE minigestor_vuln;
CREATE DATABASE minigestor_hard;
