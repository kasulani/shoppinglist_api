"""
    This file is required to run the application when using gunicorn
"""
from app import shoplist_api

if __name__ == '__main__':
    shoplist_api.run(host='0.0.0.0')
