class config:
    SECRET_KEY = 'QdGFPR5RzxSlhxRw3wS6'

class DevelopmentConfig(config):
    DEBUG = True
    MYSQL_DATABASE_HOST = 'localhost'
    MYSQL_DATABASE_USER = 'root'
    MYSQL_DATABASE_PASSWORD = ''
    MYSQL_DATABASE_DB = 'registro-labo'


config={
    'development':DevelopmentConfig
}