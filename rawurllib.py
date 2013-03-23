#!/usr/bin/env python

import re
import string
import rawsocket

def urlretrieve(url, file):
    """Given an URL, return the file of the page,
    if the name of the file is not specified, use index.html"""
    hostname, referer = _gethostpath(url)
    # Connect to the hostname 
    http = HTTPConnection(hostname)
    http.connect()
    http.request("GET", referer, {'Referer': referer})
    response = http.get_response()
    while response == None:
        http.connect()
        http.request("GET", referer, {'Referer': referer})
        response = http.get_response()
    http.close()
    # Write the HTTP response to file
    file = open(file, "w")
    file.write(response.body)
    file.close()

def getname(url):
    """ Given an URL, return the page name of the html file """
    m = re.search("[/]{2}(.*)[/](.*[.]html)", url)
    if m:
        return m.group(2)
    return "index.html"

def gethost(url):
    host, path = _gethostpath(url)
    return host

def _gethostpath(url):
    host = None
    path = None
    m = re.search("http:[/]{2}(.*?)([/].*)", url)
    if m:
        host = m.group(1)
        path = m.group(2)
    else:
        m = re.search("http:[/]{2}(.*)", url)
        if m:
            host = m.group(1)
            path = "/"
    return host, path


class HTTPRequest:
    def __init__(self, method, url, headers, body=''):
        self.method = method
        self.url = url
        self.headers = headers
        self.body = body

    def __str__(self):
        initial_line = [ self.method, self.url, 'HTTP/1.1' ]
        request_message = [ string.join(initial_line, ' ') ]
        for head in self.headers:
            request_message.append(head + ': ' + self.headers[head])
        request_message.append('')
        request_message.append(self.body)
        return string.join(request_message, '\r\n')


class HTTPResponse:
    def __init__(self, status, reason, headers, body=None):
        self.status = status
        self.reason = reason
        self.headers = headers
        self.body = body


class HTTPConnection:
    def __init__(self, hostname, port=80):
        self.port = port
        self.response = None
        self.hostname = hostname

    def connect(self):
        self.conn = rawsocket.RawSocket()
        self.conn.connect((self.hostname, self.port))

    def request(self, method, url, headers={}, body=""):
        self.url = url
        headers['Host'] = self.hostname
        message = HTTPRequest(method, url, headers, body)
        return self.conn.send(str(message))
        
    def get_response(self):
        data = self.conn.recv(4096)
        # if the length of the data is 0
        if data == None or len(data) == 0:
            return None 
        data_list = data.split('\r\n')
        # Parse the data
        header_list = []
        body_list = []
        index = data_list.index('')
        header_list = data_list[:index]
        if header_list == ['0']:
            return None
        body_list = data_list[index + 1:]
        init = header_list[0].split(' ') #
        # Get the status and reason
        if len(init) < 2:
            return HTTPResponse(0, '', '')
        status = int(init[1])
        reason = init[2]
        # Get the headers
        header_list = [ header.split(': ') for header in header_list ]
        headers = {} 
        for header in header_list[1:]:
            headers[header[0]] = header[1]
        # Get the body
        bodybuffer = string.join(body_list,'\r\n')
        body = ''
        if headers.has_key('Transfer-Encoding') and \
           headers['Transfer-Encoding'] == 'chunked':
        # If it is chunked data, it will end until there is a zero
        # number\r\nstring\r\nnumber\r\nstring\r\n0\r\n\r\n
            current_size = 1
            while not current_size == 0 and not bodybuffer == '':
                end_index = bodybuffer.find('\r\n')
                current_size = int(bodybuffer[:end_index], 16)
                bodybuffer = bodybuffer[end_index + 2:]
                read_size = 0
                while read_size < current_size:
                    end_index = bodybuffer.find('\r\n')
                    if end_index == -1 or end_index < current_size:
                        recv = self.conn.recv(4096)  
                        if recv == None:
                            return None
                        bodybuffer += recv
                    elif end_index == current_size:
                        read_size = current_size
                        body += bodybuffer[:end_index]
                        bodybuffer = bodybuffer[end_index + 2:]
        # If it is the regular data given the length, it will end until
        # data with the given length is all received
        elif headers.has_key('Content-Length'):
            bodybuffer = string.join(body_list, '\r\n')
            total_size = int(headers['Content-Length'], 10)
            if total_size > 0:
                while len(bodybuffer) < total_size:
                    recv = self.conn.recv(4096) 
                    if recv == None:
                        return None
                    bodybuffer +=  recv
                body = bodybuffer
                
        return HTTPResponse(status, reason, headers, body)
        
    def close(self):
        self.conn.close()
   

def main():
    """ Login the host with the given username and password,
    if there is a wrong password, it should be stopped """




if __name__ == '__main__': 
    main()
