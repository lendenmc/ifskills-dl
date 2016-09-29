#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
import re
import json
import io
from zipfile import ZipFile

import requests
from requests.utils import get_netrc_auth
from requests.exceptions import RequestException
from bs4 import BeautifulSoup


class LoginError(Exception):
    pass


class LogoutError(Exception):
    pass


class AuthenticationError(Exception):
    pass


class ClearoutError(Exception):
    pass


class DownloadError(Exception):
    pass


class HTMLError(Exception):
    pass


class ResponseParser(object):

    error_prefix = "Error: "

    def __init__(self, response, error_type, stream=False):
        self.error_type = error_type
        self.action = self.error_prefix + \
            self.error_type.__name__.rstrip('Error') + \
            ' attempt'
        self.response = response
        if not self.response:
            raise self.error_type(self.action + " didn't return anything")
        self.stream = stream
        self.message = self.read_text()
        self.error_msg = self.get_explicit_error()
        self.is_login_error = self.has_error_prefix("Login")
        self.is_clearout_error = self.has_error_prefix("Clearout")
        self.is_authentication_error = self.has_error_prefix("Authentication")

    def read_text(self):
        if self.stream:
            return None
        return self.response.text

    def get_explicit_error(self):
        if self.message and self.message.startswith('error'):
            error_msg = self.message.strip("error::").rstrip('.')
            return error_msg

    def has_error_prefix(self, prefix):
        name = self.error_type.__name__
        return name.startswith(prefix)

    def get_clearout_param(self):
        test_substring = re.compile('clearSession\(\'(\S+)\'\)')
        match = re.search(test_substring, str(self.error_msg))
        if match:
            param = match.group(1)
            return param

    def get_multiple_sessions_error_msg(self):
        test_substring = re.compile('\. If you believe this is an error.+')
        if not re.search(test_substring, str(self.error_msg)):
            return
        # remove browser-dependent part of the error message
        return re.sub(test_substring, '', self.error_msg)

    def test_multiple_sessions_error(self, login_attempts):
        msg = self.get_multiple_sessions_error_msg()
        if msg is None:
            return False
        if not self.is_login_error:
            raise self.error_type(self.error_prefix + msg)
        clearout_param = self.get_clearout_param()
        if login_attempts > 1 or clearout_param is None:
            advice = "Please manually clear out of any browser session"
            raise LoginError(advice)
        print(msg, file=sys.stderr)
        return clearout_param

    def test_cookies_error(self):
        test_substring = re.compile('.+browser that accepts cookies')
        if re.match(test_substring, str(self.error_msg)):
            msg = self.error_prefix + \
                "Session aborted for some unexpected reason"
            raise self.error_type(msg)
        return False

    def raise_default_error(self):
        if not self.error_msg:
            raise self.error_type
        elif self.is_login_error or self.is_clearout_error:
            raise self.error_type(self.error_msg)
        else:
            msg = self.action + " failed\n" + self.error_msg
            raise self.error_type(msg)

    @classmethod
    def test_course_title(cls, html, course_id):
        href = '/product.html?sku=' + course_id
        title = html.find('a', {
            'href': href
        })
        if title is None:
            msg = cls.error_prefix + \
                "Authentication attempt failed\n" + \
                "Invalid course id: " + course_id
            raise AuthenticationError(msg)
        return title.contents[0]

    @classmethod
    def test_html(cls, name, tag, attrs, index, html):
        selection = html.findAll(tag, attrs)
        msg = cls.error_prefix + "Cannot find any " + name + " for this course"
        if len(selection) == 0:
            raise HTMLError(msg)
        if index is not None:
            try:
                selection = selection[index]
            except IndexError:
                raise HTMLError(msg)
        return selection


class Session(object):

    def __init__(self, session):
        self.session = session
        self.host = "https://learn.infiniteskills.com/"
        self.ajax_headers = self.get_ajax_headers()
        self.login_attempts = 0

    def __enter__(self):
        self.try_login()
        print("")
        return self

    def __exit__(self, type, value, traceback):
        errors_without_traceback = [
            AuthenticationError,
            HTMLError,
            DownloadError,
            RequestException,
            KeyboardInterrupt
        ]
        if type in errors_without_traceback:
            if type is not KeyboardInterrupt:
                print(value, file=sys.stderr)
            self.try_logout()
            sys.exit(1)
        self.try_logout()

    def force_exit(self, error, msg=None):
        if msg is not None:
            msg = ResponseParser.error_prefix + msg
            print(msg, file=sys.stderr)
        raise SystemExit(error)

    def try_login(self):
        print("Logging into account")
        try:
            self.login_attempts += 1
            self.startup()
            self.login()
        except (LoginError, RequestException) as e:
            msg = "Cannot log into account"
            self.force_exit(e, msg)
        except ClearoutError as e:
            msg = "Cannot clear out of all active sessions"
            self.force_exit(e, msg)
        except KeyboardInterrupt as e:
            self.force_exit(e)

    def try_logout(self):
        try:
            self.logout()
        except RequestException as e:
            msg = "Cannot log out of account"
            self.force_exit(e, msg)
        except KeyboardInterrupt:
            print("")

    def check_response(self, response, error_type, **kwargs):
        parser = ResponseParser(response, error_type, **kwargs)
        if parser.error_msg:
            self.manage_errors(parser)

    def manage_errors(self, parser):
        login_attempts = self.login_attempts
        clearout_param = parser.test_multiple_sessions_error(login_attempts)
        if clearout_param:
            print("So clearing out of all active sessions")
            self.clearout_browser_sessions(clearout_param)
            print("Trying to log into account again")
            self.try_login()
        else:
            parser.test_cookies_error()
            parser.raise_default_error()

    def clearout_browser_sessions(self, param):
        url = self.host + "ajax/login.html"
        params = {
            'action': 'clear',
            'n': param
        }
        try:
            r = self.session.get(url, headers=self.ajax_headers, params=params)
        except RequestException as e:
            raise ClearoutError(e)
        self.check_response(r, ClearoutError)

    def startup(self):
        url = self.host + "login.html"
        r = self.session.get(url)
        self.check_response(r, LoginError)

    def login(self):
        url = self.host + "ajax/login.html"
        data = self.get_credentials()
        r = self.session.post(url, headers=self.ajax_headers, data=data)
        self.check_response(r, LoginError)

    def logout(self):
        url = self.host + "login.html"
        params = {
            'action': 'logout'
        }
        print("")
        print("Logging out of account")
        r = self.session.get(url, params=params)
        self.check_response(r, LogoutError)

    def authenticate(self, course_id):
        url = self.host + "player.html"
        params = {
            'sku': course_id
        }
        print("Authenticating course " + course_id)
        r = self.session.get(url, params=params)
        self.check_response(r, AuthenticationError)
        html = BeautifulSoup(r.content, 'html.parser')
        ResponseParser.test_course_title(html, course_id)
        return r

    def get_credentials(self):
        auth = get_netrc_auth(self.host)
        if not auth:
            msg = "netrc missing or no credentials found in netrc"
            raise LoginError(msg)
        username, password = auth
        data = {
            'username': username,
            'password': password
        }
        return data

    @staticmethod
    def get_ajax_headers():
        headers = {
            'X-Requested-With': 'XMLHttpRequest',
        }
        return headers


class Course(object):

    def __init__(self, id, content):
        self.id = id
        self.html = BeautifulSoup(content, 'html.parser')
        self.title = self.get_title()
        self.resource_host = "http://bitcast-r.v1.iad1.bitgravity.com/"
        self.sections = self.get_sections()
        self.lectures = self.get_lectures()
        self.working_files_id = self.get_working_files_id()
        print("Checking into course: " + self.title)

    def get_title(self):
        title = ResponseParser.test_course_title(self.html, self.id)
        return title

    def test_html(self, name, tag, attrs, index=None, html=None):
        if html is None:
            html = self.html
        return ResponseParser.test_html(name, tag, attrs, index, html)

    def get_sections(self):
        sections = {}
        raw_sections = self.test_html('sections', 'a', {
            'href': re.compile('#section[0-9]+')
        })
        for section in raw_sections:
            name = re.sub(r'[\t\n]', '', section.contents[0]).strip(' ')
            id = section['href'][1:]
            sections[id] = name
        return sections

    def get_lectures(self):
        metadata = self.get_lectures_metadata()
        placeholders = self.get_lectures_placeholders()
        for lecture in metadata:
            placeholder = placeholders[lecture['title']]
            for key in placeholder:
                lecture[key] = placeholder[key]
        return metadata

    def get_lectures_metadata(self):
        scripts = self.test_html('lectures', 'script', {
            'type': 'text/javascript'
        }, index=2)
        metadata = scripts.contents[0]
        metadata = metadata.split('[', 1)[1].split(']', 1)[0]
        metadata = re.sub(r'([\t\{])(\w+):', r'\1"\2":', metadata)
        metadata = re.sub(r'[\t\n]', '', metadata)
        metadata = metadata.replace('\\', '').strip().strip(',')
        metadata = "[%s]" % metadata
        metadata = json.loads(metadata)
        return metadata

    def get_lectures_placeholders(self):
        placeholders = {}
        raw_sections = self.test_html('sections', 'div', {
            'id': re.compile('section[0-9]+')
        })
        for section in raw_sections:
            section_id = section['id']
            section_name = self.sections[section_id]
            lectures = self.test_html('lectures', 'div', {
                'class': 'tutorial-item'
            }, html=section)
            for lecture in lectures:
                title = lecture.contents[0].rsplit(' (', 1)[0]
                index = lecture['id'].rsplit('_', 1)[1]
                placeholders[title] = {
                    'index': index,
                    'section': section_name
                }
        return placeholders

    @staticmethod
    def makedir(dirname):
        if not os.path.exists(dirname):
            os.makedirs(dirname)

    def makedirs(self):
        course_dirname = self.title
        self.makedir(course_dirname)
        section_dirnames = self.sections.values()
        for section in section_dirnames:
            self.makedir(course_dirname + '/' + section)

    @staticmethod
    # output format: '?e=1672341893&h=8d8fba20cd6a39739114e23464be721&pos=0'
    def authenticate(lecture, session):
        url = session.host + "ajax/player.html"
        mediaid = lecture['mediaid'].split('^')
        params = {
            'action': 'hash',
            't': mediaid[1],
            'index': lecture['index'],
            'file': lecture['file'],
            'vid': mediaid[0]
        }
        print("Authenticating lecture: " + lecture['title'])
        auth_params = session.session.get(url,
                                          headers=session.ajax_headers,
                                          params=params)
        session.check_response(auth_params, AuthenticationError)
        if auth_params.text.startswith('<!DOCTYPE html>'):
            # try a second time
            auth_params = session.session.get(url,
                                              headers=session.ajax_headers,
                                              params=params)
            session.check_response(auth_params, AuthenticationError)
            if auth_params.text.startswith('<!DOCTYPE html>'):
                msg = ResponseParser.error_prefix + \
                    "No authentication params were returned"
                raise AuthenticationError(msg)
        return auth_params.text

    def make_filename(self, lecture):
        short_filename = lecture['file'].rsplit('/', 1)[-1]
        name, extension = os.path.splitext(short_filename)
        filename = name + '. ' + lecture['title'] + extension
        dirname = self.title + '/' + lecture['section'] + '/'
        return dirname + filename

    @staticmethod
    def stream(streaming_file, local_file):
        with open(local_file, 'wb') as f:
            for chunk in streaming_file.iter_content(chunk_size=1024):
                if chunk:
                    f.write(chunk)

    def download(self, lecture, session):
        local_file = self.make_filename(lecture)
        if os.path.isfile(local_file):
            print("Skipping download of lecture: {}".format(lecture['title']))
            print("Reason: file \"{}\" already exists".format(local_file))
            return
        url = self.resource_host + "infiniteskills/"
        url += lecture['file'].split('/', 3)[3]
        auth_params = self.authenticate(lecture, session)
        url += auth_params
        print("Downloading file " + url)
        streaming_file = session.session.get(url, stream=True)
        session.check_response(streaming_file, DownloadError, stream=True)
        self.stream(streaming_file, local_file)

    def get_working_files_id(self):
        working_files = self.html.find('form', {'id': 'filedownload'})
        if working_files is not None:
            working_files_id = working_files.option['value']
            return working_files_id

    def authenticate_working_files(self, session):
        if self.working_files_id is None:
            print("No working files for this course")
            return
        ajax_headers = session.ajax_headers
        url = session.host + "ajax/history.html"
        params = {
            'event': 'file',
            'id': self.working_files_id
        }
        print("Authenticating working files id: " + self.working_files_id)
        zip_url = session.session.get(url, params=params, headers=ajax_headers)
        session.check_response(zip_url, AuthenticationError)
        if zip_url.text.startswith('<!DOCTYPE html>'):
            msg = ResponseParser.error_prefix + "No zip file url was returned"
            raise AuthenticationError(msg)
        return zip_url.text

    def download_working_files(self, session):
        zip_url = self.authenticate_working_files(session)
        if zip_url is None:
            return
        print("Downloading working files " + zip_url.strip('\n'))
        zip_file = session.session.get(zip_url, stream=True)
        session.check_response(zip_file, DownloadError, stream=True)
        with ZipFile(io.BytesIO(zip_file.content)) as myzip:
            myzip.extractall(self.title)


if __name__ == "__main__":
    course_ids = sys.argv[1:]
    if len(course_ids) == 0:
        msg = ResponseParser.error_prefix + \
            "Please provide at least one course id as argument"
        raise SystemExit(msg)
    with requests.Session() as s, Session(s) as session:
        for course_id in course_ids:
            course_content = session.authenticate(course_id).content
            course = Course(course_id, course_content)
            course.makedirs()
            course.download_working_files(session)
            for lecture in course.lectures:
                course.download(lecture, session)
