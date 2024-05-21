class config:
    SECRET_KEY = 'QdGFPR5RzxSlhxRw3wS6'

class DevelopmentConfig(config):
    DEBUG = True
    MYSQL_DATABASE_HOST = 'localhost'
    MYSQL_DATABASE_USER = 'root'
    MYSQL_DATABASE_PASSWORD = ''
    MYSQL_DATABASE_DB = 'registro-labo'

SECRET_KEY_CIFRADO = b'yyEkl5Mw3898YqMsWxT2VpPxowT6uYTLT3I61SyCBds='
config={
    'development':DevelopmentConfig
}