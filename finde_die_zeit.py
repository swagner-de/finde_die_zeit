#!/usr/bin/env python3
import os
import datetime

from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate

import logging
from pathlib import Path
import signal
import smtplib
import sys
from threading import Event
from typing import Dict, List, Callable, Any, Optional

from anticaptchaofficial.friendlycaptchaproxyless import *
import click
from fake_useragent import UserAgent
from lxml import html
import requests
import yaml

LOG = logging.getLogger(__name__)
formatter = logging.Formatter('%(levelname)s %(asctime)s %(message)s')
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(formatter)
LOG.addHandler(handler)

ALLOWED_FORMATS = ['pdf', 'epub']
CURRENT_RELEASE_URL_BUTTON_TEXT = 'ZUR AKTUELLEN AUSGABE'
RELEASE_NAME_PREFIX = 'DIE ZEIT'

TERMINATE = Event()

def solve_captcha(anti_captcha_key: str, action_url: str, site_key: str, cookies) -> str:
    solver = friendlyCaptchaProxyless()
    solver.set_key(anti_captcha_key)
    solver.set_website_url(action_url)
    solver.set_website_key(site_key)
    solver.set_cookies(cookies)

    LOG.debug(f'Solving captcha for {action_url} with site key {site_key}')
    token = solver.solve_and_return_solution()
    if token != 0:
        LOG.debug(f'Solved captcha, got token {token}')
        return token
    else:
        LOG.error(f'Error solving captcha: {solver.error_code}')
        exit(1)

def login(username: str, password: str, anti_captcha_api_key: str):
    session = requests.Session()
    session.headers.update({'User-Agent': UserAgent().random})

    init_url = "https://login.zeit.de/realms/zeit-online-public/protocol/openid-connect/auth?client_id=member&response_type=code&scope=openid&redirect_uri=https%3A%2F%2Fpremium.zeit.de"

    response = session.get(init_url)
    LOG.debug(f'Forwarded to login paged with status code {response.status_code}')

    tree = html.fromstring(response.text)
    form = tree.xpath('//form[@id="kc-form-login"]')[0]

    site_key = form.xpath('.//div[contains(@class, "frc-captcha")]/@data-sitekey')[0]

    action_url = form.attrib.get("action")
    if action_url.startswith("/"):
        action_url = "https://login.zeit.de" + action_url
    LOG.debug(f'Action URL for login form: {action_url}')

    form_data = {}
    for input_tag in form.xpath('.//input'):
        name = input_tag.attrib.get("name")
        value = input_tag.attrib.get("value", "")
        if name:
            form_data[name] = value

    form_data["username"] = username
    form_data["password"] = password
    form_data["rememberMe"] = "on"

    form_data["frc-captcha-response"] = solve_captcha(anti_captcha_api_key, action_url, site_key, session.cookies.get_dict())
    LOG.debug(f'Solved captcha, solution added to form data: {form_data["frc-captcha-response"]}')

    LOG.info('Got captcha solution, submitting login form')
    session.post(action_url, data=form_data, headers={'Content-Type': 'application/x-www-form-urlencoded',})
    if not any(c.startswith('zeit_sso_session') for c in session.cookies.get_dict().keys()):
        LOG.error(f'SSO cookie not found, login failed. Expected cookie starting with "zeit_sso_session", got '
                  f'{session.cookies.get_dict().keys()}')
        exit(1)
    LOG.info('Login successful, got zeit_sso_session cookie')
    return session

def get_release(session: requests.Session, release: int):
    url = "https://epaper.zeit.de/abo/diezeit"
    search_results = session.get(url)
    
    page = html.fromstring(search_results.text)
    xpath_release_name = f'*[starts-with(text(), "{RELEASE_NAME_PREFIX}")]/text()'
    
    def found_not_one(result, error_msg, unique=False):
        if unique:
            result = set(result)
        if not result:
            LOG.error(f'Could not find {error_msg}')
            exit(1)
        if len(result) > 1:
            LOG.error(f'Found multiple {error_msg}')
            exit(1)
        return result.pop()
    
    if release == 0:
        xpath_current_release_div = f'//div[a[contains(text(), "{CURRENT_RELEASE_URL_BUTTON_TEXT}")]]'
        current_release_div = page.xpath(xpath_current_release_div)
        current_release_div = found_not_one(current_release_div,
                                            f'<div> with <a> containing text {xpath_current_release_div}')
        
        current_release_url = found_not_one(current_release_div.xpath('./a/@href'),
                                            'a/href in <div> of current release', unique=True)

        current_release_name = found_not_one(current_release_div.xpath(f'.//{xpath_release_name}'),
                                            f'{xpath_release_name} in <div> of current release', unique=True)                                                
        return current_release_url, current_release_name

    raise NotImplementedError('Previous release not implemented yet')

def check_logged_in(session: requests.Session) -> bool:
    """Check if the session is logged in by looking for the zeit_sso_session cookie"""
    
    if not any(c.startswith('zeit_sso_session') for c in session.cookies.get_dict().keys()):
        LOG.info('No zeit_sso_session cookie found, not logged in')
        return False
    response = session.get('https://epaper.zeit.de')
    if response.status_code == 200:
        LOG.info('Tried to access https://epaper.zeit.de, got 200 OK')
        page = html.fromstring(response.text)
        xpath_current_release_div = f'//div[a[contains(text(), "{CURRENT_RELEASE_URL_BUTTON_TEXT}")]]'
        current_release_div = page.xpath(xpath_current_release_div) 
        if not current_release_div:
            LOG.info(f'Got 200 when verifying login, but could not find current release div with xpath "{xpath_current_release_div}"')
            return False
        return True
    LOG.debug(f'Tried to access https://epaper.zeit.de, got {response.status_code} {response.reason}')
    return False

def get_download_urls(session: requests.Session, release_home_url: str, formats: List[str]) -> Dict[str, str]:
    base_url = f'https://epaper.zeit.de'
    resp = session.get(f'{base_url}{release_home_url}')
    page = html.fromstring(resp.text)
    download_buttons_xpath = '//div[@class="download-buttons"]/a'
    download_buttons = page.xpath(download_buttons_xpath)
    if not download_buttons:
        LOG.error(f'Could not find any download buttons with xpath "{download_buttons_xpath}"')
        exit(1)

    url_map = dict()
    for button in download_buttons:
        for format in formats:
            if format in button.text.lower():
                LOG.debug(f'Found download button for format {format}')
                url = button.attrib['href']
                if url.startswith('http'):
                    url_map[format] = url
                else:
                    url_map[format] = f'{base_url}{url}'

    for format in formats:
        if format not in url_map:
            LOG.error(f'Could not find download button for format {format}'
                      f'Looked for {format} in button text '
                      f'{", ".join(x.text.lower().strip() for x in download_buttons)}')

    LOG.debug(f'Found download URLs {url_map}')
    return url_map

def fetch_file(session: requests.Session, url: str, release_name: str, format: str, library_path: Path):
    local_filename = f'{release_name}.{format}'.replace(' ', '_').replace('/', '-')
    local_file = library_path.joinpath(local_filename)
    if local_file.exists():
        LOG.info(f'Skipping {local_filename} download, already downloaded')
        return local_file

    LOG.info(f'Downloading {url} > {local_file.as_posix()}')
    response = session.get(
        url=url,
        stream=True
    )

    if response.status_code != 200:
        return False
    with local_file.open('wb') as f:
        for chunk in response.iter_content(chunk_size=1024):
            if chunk:  # filter out keep-alive new chunks
                f.write(chunk)
    return local_file

def send_mail(send_from:str, send_to: str, file: Path,
              server:str, port: int,
              smtp_user:str, smtp_password:str, start_tls= True):
    
    LOG.info(f'Sending file {file.name} to {send_to}')

    msg = MIMEMultipart()
    msg['From'] = send_from
    msg['To'] = send_to
    msg['Date'] = formatdate(localtime=True)
    msg['Subject'] = file.name

    msg.attach(MIMEText(file.name))

    with file.open("rb") as f:
        part = MIMEApplication(
            _data=f.read(),
        )
        part['Content-Disposition'] = 'attachment; filename="%s"' % file.name
        msg.attach(part)

    smtp = smtplib.SMTP(server, port)
    if start_tls:
        smtp.starttls()
    smtp.login(smtp_user, smtp_password)
    smtp.send_message(msg)
    smtp.close()

def is_sent(filename: str, recipient: str, history_file: Path):
    if not history_file.exists():
        return False
    with history_file.open('r') as f:
        history = yaml.safe_load(f)
        if not history:
            return False
        return history.get(filename, {}).get(recipient, False)
        

def add_sent(filename: str, recipient: str, history_file: Path):
    now =  datetime.datetime.now(datetime.UTC)
    if history_file.exists():
        with history_file.open('r') as f:
            history = yaml.safe_load(f)
            if not history:
                history = {}
    else:
        history = {}
    history.setdefault(filename, {})
    history[filename][recipient] = now
    with history_file.open('w') as f:
        yaml.dump(history, f)

def send_email_if_not_done_already(history_file: Path, file: Path, recipients: List[str], send_from:str,
                                   smtp_server:str, smtp_port: int,
                                   smtp_user:str, smtp_password:str, start_tls= True,
                                   force_send=False):
    for recipient in set(recipients):
        if force_send:
            LOG.info(f'Always sending {file.name} email to {recipient}.')
        else:
            if is_sent(file.name, recipient, history_file):
                LOG.info(f'Already sent {file.name} email to {recipient}')
                continue
            send_mail(send_from, recipient, file, smtp_server, smtp_port, smtp_user, smtp_password, start_tls)
            add_sent(file.name, recipient, history_file)
            
@click.group()
@click.option('--email', type=str, required=True,
        help='Email of your Zeit Premium account')
@click.option('--password', type=str, required=True,
        help='Password')
@click.option('--format', type=click.Choice(ALLOWED_FORMATS, case_sensitive=False), multiple=True,
              required=True, help='Format to download')
@click.option('--log-level', type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']),
              default='INFO', help='Log level')
@click.option('--library-path', type=click.Path(dir_okay=True, file_okay=False), required=True,
              default='Die_Zeit', help='Path to library')
@click.option('--anti-captcha-api-key', type=str, default=None,)
@click.pass_context
def group(ctx, **kwargs):
    LOG.setLevel(kwargs.pop('log_level'))
    ctx.ensure_object(dict)
    library_path = kwargs['library_path'] = Path(kwargs['library_path'])
    if not library_path.exists():
        library_path.mkdir()
    ctx.obj.update(kwargs)
    

@group.command()
@click.option('--release-date', type=click.DateTime(formats=["%Y-%m-%d", "%d.%m.%Y"]),
              help='Use a release date instead of a relase number')
@click.option('--previous-release', type=click.IntRange(0, 52),
              help='Download the nth release from the current one, the current one is 0' )
@click.option('--session-file', type=click.Path(dir_okay=False, file_okay=True),
              required=False, help='Path to session file, will be created if not exists')
@click.pass_context
def now(ctx, **kwargs):
    """Download the Zeit epaper right here, right now"""

    if kwargs['release_date'] and kwargs['previous_release']:
        LOG.error('Please specify either --release-date or --previous-release, not both')
        exit(1)
    kwargs.update(ctx.obj)
    _download(**kwargs)


def _download(email: str, password:str, format: List[str], release_date: datetime, previous_release: int,
              library_path: Path, anti_captcha_api_key: str, session_file: Optional[Path] = None):
    
    session = requests.Session()
    if restored_session := session_file and session_file.exists():
        LOG.debug(f'Loading session from {session_file}')
        data = yaml.safe_load(session_file.read_text())
        if not data:
            data = {}
            LOG.warning(f'Session file {session_file} is empty, logging in again')
            restored_session = False
        headers = data.get('headers', {})
        cookies = data.get('cookies', {})
        session.cookies.update(requests.utils.cookiejar_from_dict(cookies))
        session.headers.update(headers)

    if not restored_session or not check_logged_in(session):
        LOG.info('Session not restored or not logged in, logging in now')
        if restored_session:
            session_file.unlink()
        session = login(email, password, anti_captcha_api_key)
            
    release_url, release_name = get_release(session, previous_release)
    download_urls = get_download_urls(session, release_url, format)
    local_filenames = [fetch_file(session, url, release_name, format, library_path)
                       for format, url in download_urls.items()]
    if session_file:
        LOG.info(f'Saving session to {session_file}')
        yaml_data = yaml.safe_dump({
            'headers': dict(session.headers),
            'cookies': dict(requests.utils.dict_from_cookiejar(session.cookies))
        })
        with session_file.open('wb') as f:
            f.write(yaml_data.encode())
    return local_filenames

def sig_received(signo, _frame):
    LOG.info(f'Received {signo}, terminating')
    TERMINATE.set()

@group.command()
@click.option('--interval', type=int, default=4,
              help='Check for new releases every n hours')
@click.pass_context
def wait_for_next_release(ctx, interval: int, **kwargs):
    """Wait for the next "Die Zeit" epaper release and download it"""
    kwargs.update(ctx.obj)
    _wait_for_next_release(interval, **kwargs)

def _wait_for_next_release(interval: int, file_handler_func: Optional[Callable] = None, file_handler_args: Dict[str, Any] = dict(),
                           **kwargs):
    for sig in ('SIGTERM', 'SIGHUP', 'SIGINT'):
        signal.signal(getattr(signal, sig), sig_received);
    
    kwargs['previous_release'] = 0
    kwargs['release_date'] = None
    wait = interval*60*60
    while not TERMINATE.is_set():
        files = _download(**kwargs)
        for file in files:
            if file_handler_func:
                LOG.debug(f'Calling file handler function with {file}')
                file_handler_func(file=file, **file_handler_args)
        LOG.info(f'Waiting {wait} seconds')
        TERMINATE.wait(wait)

@group.command()
@click.option('--interval', type=int, default=4,
              help='Check for new releases every n hours')
@click.option('--force-send', is_flag=True, default=False,
              help='Send email even if already sent')
@click.option('--recipients', type=str, multiple=True, required=True,
              help='Email addresses of recipients',
              envvar='FINDE_DIE_ZEIT_RECIPIENTS')
@click.option('--send-from', type=str, required=True,
              help='Email address of sender',
              envvar='FINDE_DIE_ZEIT_SEND_FROM')
@click.option('--smtp-server', type=str, required=True,
              help='SMTP server',
              envvar='FINDE_DIE_ZEIT_SMTP_SERVER')
@click.option('--smtp-port', type=int, required=True, default=587,
              help='SMTP port',
              envvar='FINDE_DIE_ZEIT_SMTP_PORT')
@click.option('--smtp-user', type=str, required=False,
              help='SMTP user, default will be set to --send-from',
              envvar='FINDE_DIE_ZEIT_SMTP_USER')
@click.option('--smtp-password', type=str, required=True,
              help='SMTP password',
              envvar='FINDE_DIE_ZEIT_SMTP_PASSWORD')
@click.option('--start-tls', is_flag=True, default=False,
              help='Use STARTTLS',
              envvar='FINDE_DIE_ZEIT_SMTP_STARTTLS')
@click.option('--history-file', type=click.Path(dir_okay=False), required=True,
              default='history.yaml', help='Path to history file')
@click.pass_context
def wait_for_next_release_and_send(ctx, interval: int, **kwargs):
    """Same as "wait-for-next-release" but will send it to a list of mail recipients - most likely
    a list of kindle emails"""

    kwargs['history_file'] = Path(kwargs['history_file'])

    if os.environ.get('FINDE_DIE_ZEIT_SESSION_FILE'):
        ctx.obj['session_file'] = Path(os.environ['FINDE_DIE_ZEIT_SESSION_FILE'])

    if not kwargs['smtp_user']:
        kwargs['smtp_user'] = kwargs['send_from']

    file_handler_func = send_email_if_not_done_already

    _wait_for_next_release(interval,
                           file_handler_func=file_handler_func, file_handler_args=kwargs,
                           **ctx.obj)

if __name__ == "__main__":
    group(auto_envvar_prefix='FINDE_DIE_ZEIT')