#*** See: http://webpy.org/docs/0.3/tutorial

#*** Run web server:
# python websvr.py 1234
# where 1234 is the TCP port number to listen on

#*** Install with:
# sudo easy_install web.py

# Version 0.3

import web

urls = (
    '/', 'index',
    '/80', 'index80',
    '/1234', 'index1234',
)

class index:
    def GET(self):
        raise web.seeother('/static/index.html')

class index80:
    def GET(self):
        raise web.seeother('/static/index80.html')
        
class index1234:
    def GET(self):
        raise web.seeother('/static/index1234.html')

if __name__ == "__main__":
    app = web.application(urls, globals())
    app.run()
