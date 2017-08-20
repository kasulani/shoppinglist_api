"""
    Shopping List API
    Created: 20 - August - 2017
    Author: Emmanuel King Kasulani
    Email: kasulani@gmail.com
"""
from app import shoplist_api, manager

shoplist_api.logger.info("Starting API server...")
manager.run()
