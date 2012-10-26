#!/usr/bin/env python

import gzip
from cStringIO import StringIO


def http_split(data):
    """
    Return a tuple of headers and body from an HTTP message. (dict, string)
    The HTTP response message (e.g. "HTTP/1.1 200 OK") is lost in using this method.
    """

    assert len(data) > 0, "data must be non-zero length"
    assert data.find('\r\n\r\n') > 0, "data does not appear to be a complete HTTP response message"

    # Place header and body portion into their own strings (no further data structure yet)
    headers, body = data.split('\r\n\r\n')

    return headers, body

def http_headers_dict(headers_data):
    """
    Return a dictionary of Header Key-Value pairs given a string containing \r\n delimited HTTP
    headers
    """

    # Format headers into a dictionary (ditching the HTTP xxx response message in the meantime)
    headers_dict = dict(item.split(':', 1) for item in headers_data.split('\r\n')[1:])

    return headers_dict

def http_is_gzip(data):
    """
    Returns true if (a rudimentary) check for the HTTP response being gzip-encoded is true
    """

    try:
        # If http_split returns an AssertionError, the data likely isn't an HTTP Response
        headers, body = http_split(data)
        headers = http_headers_dict(headers)
    except AssertionError, ex:
        return False

    # Make keys and values lower-case (for simplified comparisons)
    headers = dict((k.lower(), v.lower()) for k,v in headers.iteritems())

    # Check if content-encoding header exists
    if not headers.has_key('content-encoding'):
        return False

    # Check if content-encoding contains gzip
    return headers['content-encoding'].find('gzip') > 0

def http_gunzip(gzdata):
    """
    Return the uncompressed data given a gzip-compressed data string
    """

    return gzip.GzipFile(fileobj=StringIO(gzdata)).read()

def http_gzip(plaintext, level=9):
    """
    Return the gzip binary data for use in HTTP messages given a plaintext string, and optionaly
    a compression level (default is level 9)
    """

    gzip_mine = StringIO()
    gzipper = gzip.GzipFile(fileobj=gzip_mine, mode='wb', compresslevel=level)
    gzipper.write(plaintext)
    gzipper.close()

    gzip_mine.seek(0)
    my_gz = gzip_mine.read()

    return my_gz

def http_reconstruct_message(headers, body):
    """
    Given a string of headers and a string of an HTTP body, return them joined with \r\n\r\n per the HTTP spec
    This method is not intelligent, it will not avoid duplicate \r\n\r\n strings if the input already contains them
    """

    return '\r\n\r\n'.join( (headers, body) )
