from subprocess import Popen, PIPE
import os
import re
import time
import threading
from kazoo.client import KazooClient
from kazoo.exceptions import NodeExistsError, NoNodeError
import logging
import json
import sys
import tempfile
import shutil
import platform
import datetime
import urllib.request
import urllib.parse
import urllib.error
import socket
import base64
from PyQt5 import QtCore, QtWidgets, QtGui


class Communicate(QtCore.QObject):

    auth_up = QtCore.pyqtSignal()

class Ui_MainForm(object):
    def setupUi(self, MainForm):
        MainForm.setObjectName("MainForm")
        MainForm.resize(300, 210)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(MainForm.sizePolicy().hasHeightForWidth())
        MainForm.setSizePolicy(sizePolicy)
        MainForm.setMinimumSize(QtCore.QSize(300, 210))
        MainForm.setMaximumSize(QtCore.QSize(300, 210))
        self.pushButton_2 = QtWidgets.QPushButton(MainForm)
        self.pushButton_2.setGeometry(QtCore.QRect(120, 170, 171, 32))
        self.pushButton_2.setMaximumSize(QtCore.QSize(171, 32))
        self.pushButton_2.setObjectName("pushButton")
        self.comboBox = QtWidgets.QComboBox(MainForm)
        self.comboBox.setGeometry(QtCore.QRect(50, 10, 201, 26))
        self.comboBox.setLocale(QtCore.QLocale(QtCore.QLocale.Russian, QtCore.QLocale.Russia))
        self.comboBox.setEditable(True)
        self.comboBox.setCurrentText("")
        self.comboBox.setFrame(True)
        self.comboBox.setObjectName("comboBox")
        self.pushButton = QtWidgets.QPushButton(MainForm)
        self.pushButton.setGeometry(QtCore.QRect(10, 170, 101, 32))
        self.pushButton.setMaximumSize(QtCore.QSize(101, 32))
        self.pushButton.setCheckable(False)
        self.pushButton.setDefault(False)
        self.pushButton.setObjectName("pushButton_2")
        self.label = QtWidgets.QLabel(MainForm)
        self.label.setGeometry(QtCore.QRect(10, 10, 35, 26))
        self.label.setObjectName("label")
        self.pushButton_3 = QtWidgets.QPushButton(MainForm)
        self.pushButton_3.setEnabled(False)
        self.pushButton_3.setGeometry(QtCore.QRect(10, 130, 101, 32))
        self.pushButton_3.setMaximumSize(QtCore.QSize(101, 32))
        self.pushButton_3.setAutoDefault(False)
        self.pushButton_3.setDefault(False)
        self.pushButton_3.setObjectName("pushButton_3")
        self.pushButton_4 = QtWidgets.QPushButton(MainForm)
        self.pushButton_4.setEnabled(False)
        self.pushButton_4.setGeometry(QtCore.QRect(120, 130, 171, 32))
        self.pushButton_4.setMaximumSize(QtCore.QSize(171, 32))
        self.pushButton_4.setAutoDefault(False)
        self.pushButton_4.setFlat(False)
        self.pushButton_4.setObjectName("pushButton_4")
        self.groupBox = QtWidgets.QGroupBox(MainForm)
        self.groupBox.setGeometry(QtCore.QRect(10, 40, 280, 81))
        self.groupBox.setObjectName("groupBox")
        self.label_2 = QtWidgets.QLabel(self.groupBox)
        self.label_2.setGeometry(QtCore.QRect(10, 20, 260, 16))
        self.label_2.setObjectName("label_2")
        self.label_3 = QtWidgets.QLabel(self.groupBox)
        self.label_3.setGeometry(QtCore.QRect(10, 40, 260, 16))
        self.label_3.setObjectName("label_3")
        self.label_4 = QtWidgets.QLabel(self.groupBox)
        self.label_4.setGeometry(QtCore.QRect(10, 60, 260, 16))
        self.label_4.setObjectName("label_4")

        self.retranslateUi(MainForm)
        QtCore.QMetaObject.connectSlotsByName(MainForm)

    def retranslateUi(self, MainForm):
        _translate = QtCore.QCoreApplication.translate
        MainForm.setWindowTitle(_translate("MainForm", "FlexiLigner Sync"))
        self.pushButton_2.setText(_translate("MainForm", "Завершить работу"))
        self.pushButton.setText(_translate("MainForm", "В работу"))
        self.label.setText(_translate("MainForm", "Кейс:"))
        self.pushButton_3.setText(_translate("MainForm", "Просмотр"))
        self.pushButton_4.setText(_translate("MainForm", "Завершить просмотр"))
        self.groupBox.setTitle(_translate("MainForm", "Информация по кейсу:"))
        self.label_2.setText(_translate("MainForm", " "))
        self.label_3.setText(_translate("MainForm", " "))
        self.label_4.setText(_translate("MainForm", " "))


class Ui_SettingsForm(object):
    def setupUi(self, SettingsForm):
        SettingsForm.setObjectName("SettingsForm")
        SettingsForm.resize(360, 185)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(SettingsForm.sizePolicy().hasHeightForWidth())
        SettingsForm.setSizePolicy(sizePolicy)
        SettingsForm.setMinimumSize(QtCore.QSize(360, 185))
        SettingsForm.setMaximumSize(QtCore.QSize(360, 185))
        self.pushButton_2 = QtWidgets.QPushButton(SettingsForm)
        self.pushButton_2.setGeometry(QtCore.QRect(50, 150, 113, 32))
        self.pushButton_2.setMaximumSize(QtCore.QSize(113, 32))
        self.pushButton_2.setObjectName("pushButton_3")
        self.pushButton_3 = QtWidgets.QPushButton(SettingsForm)
        self.pushButton_3.setGeometry(QtCore.QRect(200, 150, 113, 32))
        self.pushButton_3.setMaximumSize(QtCore.QSize(113, 32))
        self.pushButton_3.setObjectName("pushButton_4")
        self.tabWidget = QtWidgets.QTabWidget(SettingsForm)
        self.tabWidget.setGeometry(QtCore.QRect(10, 10, 341, 131))
        self.tabWidget.setObjectName("tabWidget")
        self.tab = QtWidgets.QWidget()
        self.tab.setObjectName("tab")
        self.lineEdit = QtWidgets.QLineEdit(self.tab)
        self.lineEdit.setGeometry(QtCore.QRect(70, 10, 191, 21))
        self.lineEdit.setObjectName("lineEdit")
        self.label = QtWidgets.QLabel(self.tab)
        self.label.setGeometry(QtCore.QRect(10, 10, 51, 16))
        self.label.setObjectName("label")
        self.lineEdit_2 = QtWidgets.QLineEdit(self.tab)
        self.lineEdit_2.setGeometry(QtCore.QRect(70, 40, 191, 21))
        self.lineEdit_2.setEchoMode(QtWidgets.QLineEdit.Password)
        self.lineEdit_2.setObjectName("lineEdit_2")
        self.label_2 = QtWidgets.QLabel(self.tab)
        self.label_2.setGeometry(QtCore.QRect(10, 40, 60, 16))
        self.label_2.setObjectName("label_2")
        self.pushButton = QtWidgets.QPushButton(self.tab)
        self.pushButton.setGeometry(QtCore.QRect(10, 70, 113, 32))
        self.pushButton.setMaximumSize(QtCore.QSize(113, 32))
        self.pushButton.setObjectName("pushButton")
        self.tabWidget.addTab(self.tab, "")
        self.tab_2 = QtWidgets.QWidget()
        self.tab_2.setObjectName("tab_2")
        self.label_3 = QtWidgets.QLabel(self.tab_2)
        self.label_3.setGeometry(QtCore.QRect(10, 10, 151, 16))
        self.label_3.setObjectName("label_3")
        self.lineEdit_3 = QtWidgets.QLineEdit(self.tab_2)
        self.lineEdit_3.setGeometry(QtCore.QRect(10, 40, 321, 21))
        self.lineEdit_3.setObjectName("lineEdit_3")
        self.pushButton_4 = QtWidgets.QPushButton(self.tab_2)
        self.pushButton_4.setGeometry(QtCore.QRect(10, 70, 113, 32))
        self.pushButton_4.setMaximumSize(QtCore.QSize(113, 32))
        self.pushButton_4.setObjectName("pushButton_5")
        self.tabWidget.addTab(self.tab_2, "")

        self.retranslateUi(SettingsForm)
        self.tabWidget.setCurrentIndex(0)
        QtCore.QMetaObject.connectSlotsByName(SettingsForm)

    def retranslateUi(self, SettingsForm):
        _translate = QtCore.QCoreApplication.translate
        SettingsForm.setWindowTitle(_translate("SettingsForm", "FlexiLigner Sync - Настройки"))
        self.pushButton_2.setText(_translate("SettingsForm", "Сохранить"))
        self.pushButton_3.setText(_translate("SettingsForm", "Отмена"))
        self.label.setText(_translate("SettingsForm", "Логин:"))
        self.label_2.setText(_translate("SettingsForm", "Пароль:"))
        self.pushButton.setText(_translate("SettingsForm", "Вход"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab), _translate("SettingsForm", "Аккаунт"))
        self.label_3.setText(_translate("SettingsForm", "Папка синхронизации:"))
        self.pushButton_4.setText(_translate("SettingsForm", "Выбрать"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_2), _translate("SettingsForm", "Папка синхронизации"))

log = logging.getLogger('flexilignersync')

lock_keys_list_background_loop = threading.Lock()
lock_keys_locks_list_background_loop = threading.Lock()
threading_event = threading.Event()



class RsyncFailed(Exception):
    """Custom exception for rsync errors"""
    pass

class StreamToLogger(object):
    """Fake file-like stream object that redirects writes to logger"""
    def __init__(self, logger, log_level=logging.INFO):
        self.logger = logger
        self.log_level = log_level
        self.linebuf = ''

    def write(self, buf):
        """method to writing stream lines to logger"""
        for line in buf.rstrip().splitlines():
            self.logger.log(self.log_level, line.rstrip())

    def flush(self):
        """fake method, that can be called by sys"""
        pass

def get_current_workdir():
    if getattr(sys, 'frozen', False):
        # The application is frozen
        workdir = os.path.dirname(os.path.abspath(sys.executable))
        log.info("frozen app, workdir is %s", workdir)
    else:
        # The application is not frozen
        workdir = os.path.dirname(os.path.abspath(__file__))
        log.info("not frozen app, workdir is %s", workdir)
    return workdir

def change_acl_for_delete_win(path):
    """Zaps the SECURITY_DESCRIPTOR's DACL on a directory entry that is tedious to
    delete.

    This function is a heavy hammer. It discards the SECURITY_DESCRIPTOR and
    creates a new one with only one DACL set to user:FILE_ALL_ACCESS.

    Used as last resort.
    """
    STANDARD_RIGHTS_REQUIRED = 0xf0000
    SYNCHRONIZE = 0x100000
    FILE_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x3ff

    import win32security
    import getpass
    user, _domain, _type = win32security.LookupAccountName('', getpass.getuser())
    log.info("windows magick user %s", user)
    sd = win32security.SECURITY_DESCRIPTOR()
    sd.Initialize()
    sd.SetSecurityDescriptorOwner(user, False)
    dacl = win32security.ACL()
    dacl.Initialize()
    dacl.AddAccessAllowedAce(win32security.ACL_REVISION_DS, FILE_ALL_ACCESS, user)
    sd.SetSecurityDescriptorDacl(1, dacl, 0)
    win32security.SetFileSecurity(path, win32security.DACL_SECURITY_INFORMATION, sd)

def rmtree_fix(func, path, exc_info):
    import stat
    if isinstance(exc_info[1], FileNotFoundError):
        return None
    try:
        log.info("rmtree fix")
        os.chmod(path, stat.S_IWUSR)
        func(path)
    except Exception as e:
        log.info("rmtree fix failed %s", repr(e))
        if windows():
            try:
                log.info("rmtree fix windows last chance")
                change_acl_for_delete_win(path)
                func(path)
            except Exception as e:
                log.info("windows last chance failed %s", repr(e))
                raise
        else:
            raise

class SshKey:
    def __init__(self):
        ssh_file = tempfile.mkstemp(prefix="fl_ssh_")
        self.path = ssh_file[1]
        self.fd = ssh_file[0]
        log.info("ssh key path %s", self.path)
        try:
            ssh_key_data = base64.b64decode(m_config['rsync']['ssh_key'])
            os.write(self.fd, ssh_key_data)
            if windows():
                change_acl_for_delete_win(self.path)
            os.close(self.fd)
        except Exception as e:
            log.info("cant create ssh key file %s", repr(e))

    def remove(self):
        try:
            log.info("removing ssh key %s", self.path)
            os.remove(self.path)
        except Exception as e:
            try:
                os.write(self.fd,"0".encode())
            except Exception as e1:
                log.info("cant truncate ssh key file %s, %s", self.path, repr(e1))
            log.info("cant delete ssh key file %s, %s", self.path, repr(e))
        return None


def load_logger(conf):
    """Create logger with path and loglevel from config."""
    path = conf['path']
    level = conf['level']
    tmpdir = tempfile.gettempdir()
    try:
        path = os.path.abspath(os.path.join(tmpdir, path))
        log.info(path)
        logdir = os.path.dirname(path)
        if not os.path.exists(logdir):
            os.makedirs(logdir, mode=0o755)
    except Exception as e:
        log.info("can't create log directory {}: {}".format(
            logdir, repr(e)))
        raise
    try:
        fh = logging.FileHandler(path, encoding='UTF-8')
        formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
        fh.setFormatter(formatter)
        log.addHandler(fh)
        numeric_level = getattr(logging, level.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError("invalid log level: {}".format(level))
        log.setLevel(numeric_level)
        logging.getLogger('http').handlers = [fh]
        sys.stdout = StreamToLogger(log, logging.INFO)
        sys.stderr = StreamToLogger(log, logging.INFO)
    except Exception as e:
        log.info("can't initialize file logger: {}".format(repr(e)))
        raise

def windows():
    system = platform.system()
    log.debug('Platform is %s', system)
    if system is 'Windows':
        return True
    return False



def init_kazoo_client(conf):
    """Setup kazoo client params and establish connection to zookeeper."""
    log.info("init kazoo")
    attempts = conf['attempts']
    delay = float(conf['attempts_delay'])
    hosts = conf['host']
    timeout = float(conf['timeout'])
    credential = ':'.join((conf['user'],
                          conf['pass_digest']))
    auth_data = [('digest', credential)]
    # http://kazoo.readthedocs.io/en/latest/api/retry.html#kazoo.retry.KazooRetry
    retry_params = dict(
        max_tries=attempts,
        delay=delay,
    )
    # http://kazoo.readthedocs.io/en/latest/api/client.html#kazoo.client.KazooClient
    log.info("createing client")
    zk = KazooClient(
        hosts=hosts,
        timeout=timeout,
    #    auth_data=auth_data,
        connection_retry=retry_params,
        command_retry=retry_params,
    )
    try:
        log.info("connecting to zookeeper")
        zk.start()
        zk.add_auth('digest', credential)
    except Exception as e:
        msg = "zookeeper connection was failed: {}".format(repr(e))
        log.info(msg)
        raise
    else:
        log.info("connected to zookeeper")
    return zk

def deinit_kazoo_client(zk):
    """Disconnect from zookeeper and cleanup kazoo client."""
    log.info("deinit kazoo client")
    try:
        zk.stop()
        zk.close()
    except Exception as e:
        log.info("stopping kazoo client was failed: %s", repr(e))


def create_lock(lock_path, lock_value):
    """Acquiring zookeeper lock."""
    full_lock_path = m_config['zookeeper']['node_path'] + "/" + lock_path
    locked = False
    lock_value_e = lock_value.encode()
    try:
        # http://kazoo.readthedocs.io/en/latest/api/client.html#kazoo.client.KazooClient.retry
        lock_node = zk.retry(
            # http://kazoo.readthedocs.io/en/latest/api/client.html#kazoo.client.KazooClient.create
            zk.create, full_lock_path, lock_value_e, None, False, False, True
        )
        if not lock_node == full_lock_path:
            raise ValueError("unexpected lock path {}, must be {}".format(
                lock_node, full_lock_path))
    except NodeExistsError:
        log.info("lock %s already exists", full_lock_path)
        locked = False
        try:
            # http://kazoo.readthedocs.io/en/latest/api/client.html#kazoo.client.KazooClient.get
            existing_lock_data = zk.retry(zk.get, full_lock_path)[0]
        except Exception as get_existing_lock_exception:
            locked = False
            log.info("getting content of existing lock was failed: %s", repr(get_existing_lock_exception))
        else:
            if existing_lock_data == lock_value_e:
                locked = True
                log.info("lock with same content already exists: %s", full_lock_path)
    except Exception as other_error:
        log.info("creating lock was failed: %s", repr(other_error))

        locked = False
    else:
        locked = True
        log.info("lock successfully acquired: %s", full_lock_path)
    return locked

def release_lock(lock_path):
    """Release zookeeper lock."""
    released = False
    full_lock_path = m_config['zookeeper']['node_path'] + "/" + lock_path
    try:
        log.info("releasing lock %s", full_lock_path)

        zk.retry(zk.delete, full_lock_path)
    except NoNodeError:
        released = True
        log.info("lock %s doesnt exist", full_lock_path)
    except Exception as e:
        released = False
        log.info("releasing lock was failed: %s", repr(e))
    else:
        released = True
        log.info("lock %s successfully released", full_lock_path)
    return released

def list_locks():
    locks = list()
    locks_base_path = m_config['zookeeper']['node_path']
    if auth_info['success']:
        try:
            log.debug("gettings list of locks")
            locks = zk.retry(zk.get_children, locks_base_path)
        except Exception as e:
            log.info("getting locks list failed: %s", repr(e))
            locks = None
    return locks

def get_lock_content(lock_path):
    content = None
    full_lock_path = m_config['zookeeper']['node_path'] + "/" + lock_path
    try:
        log.info("getting content of lock %s", full_lock_path)
        content = zk.retry(zk.get, full_lock_path)[0]
    except NoNodeError:
        log.info("lock %s doesnt exist", full_lock_path)
    except Exception as e:
        log.info("cant get content of lock %s", full_lock_path)
    return content

def to_human_readable_ts(timestamp):
    """Convert timestamp from unixtime to human readable format."""
    return datetime.datetime.fromtimestamp(int(timestamp)).strftime('%H:%M %d.%m.%Y')

def convert_win_path(path):
    if not windows():
        return path
    path_final = str()
    try:
        log.debug("convert win path from: %s", path)
        path = path.replace("\\","/")
        path_final = re.sub("^([A-Z]):", r"/cygdrive/\1", path)
    except Exception as e:
        log.info("cant convert win path: %s", repr(e))
    return path_final

def rsync(cmd):
    log.debug("rsync command: %s", ' '.join(cmd))
    attempts = range(1, m_config['rsync']['attempts'] + 1)
    delay = m_config['rsync']['attempts_delay']

    for attempt in attempts:
        log.debug("trying rsync, attempt=%d", attempt)
        rsync = Popen(' '.join(cmd),
            stdout=PIPE,
            stderr=PIPE,
            universal_newlines=True,
            shell=True,
            env=rsync_env
        )
        output = rsync.communicate()
        if rsync.returncode in [35, 30, 25, 24, 23, 22, 21, 20, 14, 13, 12, 11, 10, 6, 5, 3]:
            log.info("nonzero rsync return code: %d", rsync.returncode)
            time.sleep(delay)
            continue
        else:
            log.debug("rsync done with attempt=%d and code %d", attempt, rsync.returncode)
            break
    else:
        log.info("rsync was failed: all attempts was reached %s", ' '.join(cmd))
        raise RsyncFailed("Rsync failed after {} attempts with code {} and reason {}".format(attempts, rsync.returncode, output[1]))
    return output

def rsync_copy(from_path, to_path):
    log.info("rsync copy from %s to %s", from_path, to_path)
    cmd = [
        'rsync',
        '-rlgDHh',
        '--timeout={}'.format(m_config['rsync']['timeout']),
        '--delete',
        '--progress',
        '--append-verify',
        '-e',
        '"ssh {}"'.format(rsync_ssh_opts),
        '"{}"'.format(convert_win_path(from_path)),
        '"{}"'.format(convert_win_path(to_path))
        ]

    return rsync(cmd)

def rsync_list_server_dirs(path):
    cmd = [
        'rsync',
        '-Hh',
        '--timeout={}'.format(m_config['rsync']['timeout']),
        '--list-only',
        '--include',
        '"*/"',
        '--exclude',
        '"*"',
        '-e',
        '"ssh {}"'.format(rsync_ssh_opts),
        '"{}"'.format(path),
        '"{}"'.format(convert_win_path(u_config['sync_path'])),
        ]

    return rsync(cmd)[0]

def list_keys_dirs(path):
    output = list()
    digit = re.compile('^[0-9]+$')
    if auth_info['success']:
        try:
            rsync_result = rsync_list_server_dirs(path)
            for line in rsync_result.splitlines():
                last_column = line.split()[-1]
                if digit.match(last_column):
                    output.append(last_column)
            output.sort(key=int)
        except Exception as e:
            log.info(e)
            log.info("cant get keys list: %s", repr(e))
    return output


def keys_list_background_loop():
    global keys_list
    if lock_keys_list_background_loop.acquire(blocking=False) and not threading_event.is_set():
        try:
            log.debug("running keys_list_background updater")
            if 'keys_list' not in globals():
                keys_list = list()
            temp_keys_list = list_keys_dirs(m_config['rsync']['server'] + ":" + m_config['rsync']['keys_path'])
            log.debug("temp_keys_list done")
            log.debug(temp_keys_list)
            if keys_list and not temp_keys_list:
                log.debug("keys_list and not temp_keys_list")
            else:
                log.debug("temp_keys_list to keys_list")
            keys_list = temp_keys_list
        finally:
            lock_keys_list_background_loop.release()
    if not threading_event.is_set():
        threading.Timer(float(m_config['keys_list_background_delay']), keys_list_background_loop).start()
    return None

def parse_main_config(path):
    """Parsing configuration file, if it possible."""
    try:
        confdir = os.path.dirname(path)
        if not os.path.exists(confdir):
            raise ValueError("config path directory does not exist")
        if not os.path.exists(path):
            raise ValueError("config file does not exist")
        if not os.path.isfile(path):
            raise ValueError("config is not regular file")
        if os.path.getsize(path) == 0:
            raise ValueError("config file is empty")
        with open(path, 'r', encoding='utf-8') as f:
            conf = json.load(f, encoding='utf-8')
        return conf
    except Exception as e:
        log.info("can't load config file {}: {}".format(path, repr(e)))
        raise

def parse_user_config(path):
    """Parsing user configuration file, if it possible."""
    conf = dict()
    try:
        confdir = os.path.dirname(path)
        if not os.path.exists(confdir):
            log.info("config dir %s does not exists, creating", confdir)
            try:
                os.makedirs(confdir, mode=0o755)
            except Exception as e:
                log.info("can't create directory %s: %s", confdir, repr(e))

        if not os.path.exists(path) or not os.path.isfile(path) or os.path.getsize(path) == 0:
            log.info("config file does not exist")
        else:
            log.info("loading user config %s", path)
            with open(path, 'r', encoding='utf-8') as f:
                conf = json.load(f, encoding='utf-8')
    except Exception as e:
        log.info("can't load user config file %s: %s", path, repr(e))
    #    raise
    log.info(conf)
    return conf

def init_sync_path():
    log.info("init sync path")
    sync_path = str()
    if u_config and 'user_sync_path' in u_config and u_config['user_sync_path']:
        log.info("user_sync_path in user config ")
        sync_path = os.path.abspath(u_config['user_sync_path'])
    else:
        log.info("u_config empty or have no user_sync_path")
        try:
            sync_path = os.path.abspath(os.path.expanduser(m_config['default_sync_path']))
        except Exception as e:
            log.info("%s", repr(e))
    try:
        if not os.path.exists(sync_path):
            log.info("creating sync_path %s", sync_path)
            os.makedirs(sync_path, mode=0o755)
    except Exception as e:
        log.info("can't create directory %s: %s", sync_path, repr(e))
    u_config['sync_path'] = sync_path
    log.info("sync_path %s", u_config['sync_path'])

def keys_locks_list_background_loop():
    global keys_locks_list
    if lock_keys_locks_list_background_loop.acquire(blocking=False) and not threading_event.is_set():
        try:
            log.debug("running keys_locks_list_background updater")
            if 'keys_locks_list' not in globals():
                keys_locks_list = list()
            temp_keys_locks_list = list_locks()
            if keys_locks_list and temp_keys_locks_list is None:
                log.debug("keys_locks_list and not temp_keys_locks_list")
            else:
                log.debug("temp_keys_locks_list to keys_locks_list")
                keys_locks_list = temp_keys_locks_list
                log.debug(keys_locks_list)
        finally:
            lock_keys_locks_list_background_loop.release()
    if not threading_event.is_set():
        threading.Timer(float(m_config['keys_locks_list_background_delay']), keys_locks_list_background_loop).start()
    return None

def auth_request(login, password):

    try:
        details = urllib.parse.urlencode({ 'login': login, 'pass': password }).encode()
        url = urllib.request.Request(m_config['auth']['handler'], details)
        url.add_header("User-Agent","Mozilla/5.0 (Windows; U; Windows NT 6.0; en-US) AppleWebKit/525.13 (KHTML, like Gecko) Chrome/0.2.149.29 Safari/525.13")

        responseData = urllib.request.urlopen(url).read().decode('utf8', 'ignore')
        responseFail = False

    except urllib.error.HTTPError as e:
        responseData = e.read().decode('utf8', 'ignore')
        responseFail = False

    except urllib.error.URLError:
        responseFail = True

    except socket.error:
        responseFail = True

    except socket.timeout:
        responseFail = True

    except UnicodeEncodeError:
        log.info("[x]  Encoding Error")
        responseFail = True


    return responseData

def get_auth_info(conf):
    log.info("try to get auth info")
    auth_info = dict()
    try:
        auth_info = json.loads(auth_request(conf['login'], conf['password']))
    except Exception as e:
        log.info("get auth info failed %s", repr(e))
    log.info(auth_info)
    return auth_info

def init_auth_info():
    if auth_info['success']:
        u_config['id'] = auth_info['data']['id']
        u_config['username'] = auth_info['data']['username']
        u_config['name'] = auth_info['data']['name']
        u_config['surname'] = auth_info['data']['surname']
        u_config['patronymic'] = auth_info['data']['patronymic']
    else:
        u_config['id'] = None
        u_config['username'] = None
        u_config['name'] = None
        u_config['surname'] = None
        u_config['patronymic'] = None

class RsyncOperations(QtCore.QThread):
    def __init__(self, keys, to_server, maestro):
        QtCore.QThread.__init__(self)
        self.keys = keys
        self.to_server = to_server
        self.maestro = maestro
        self.has_error = False

    def __del__(self):
        self.wait()

    def run(self):
        if self.to_server:
            self.do_to_server()
        else:
            self.do_from_server()

    def do_from_server(self):
        log.info("from_server func")
        if self.maestro:
            log.info("maestro processing")
            maestro_server_path = m_config['rsync']['server'] + ":" + m_config['rsync']['keys_path'] + self.keys + "/diagnostics/MaestroData/"
            if windows():
                maestro_local_path = os.path.abspath(m_config['rsync']['maestrodata'])
            else:
                maestro_local_path = os.path.abspath(os.path.join(tempfile.gettempdir(), "MaestroData"))
            try:
                shutil.rmtree(maestro_local_path, ignore_errors=False, onerror=rmtree_fix)
            except FileNotFoundError as e:
                log.info("local maestro data not found %s", repr(e))
            except Exception as e:
                log.info("cant delete local maestro data %s", repr(e))
                self.has_error = True
                return None
            try:
                rsync_copy(maestro_server_path, maestro_local_path)
            except Exception as e:
                log.info("failed maestro processing %s", repr(e))
                self.has_error = True
            else:
                self.do_from_server_main()
        else:
            self.do_from_server_main()
        return None

    def do_from_server_main(self):
        try:
            log.info("diagnostics processing")
            rsync_copy(m_config['rsync']['server'] + ":" + m_config['rsync']['keys_path'] + self.keys + "/diagnostics", os.path.abspath(os.path.join(u_config['sync_path'], self.keys)))
            log.info("scans processing")
            rsync_copy(m_config['rsync']['server'] + ":" + m_config['rsync']['keys_path'] + self.keys + "/scans", os.path.abspath(os.path.join(u_config['sync_path'], self.keys)))
        except Exception as e:
            log.info("failed rsync from server %s", repr(e))
            self.has_error = True
        return None

    def do_to_server(self):
        log.info("to_server func")
        if self.maestro:
            log.info("maestro processing")
            maestro_server_path = m_config['rsync']['server'] + ":" + m_config['rsync']['keys_path'] + self.keys + "/diagnostics/MaestroData/"
            if windows():
                maestro_local_path = os.path.abspath(m_config['rsync']['maestrodata'])
            else:
                maestro_local_path = os.path.abspath(os.path.join(tempfile.gettempdir(), "MaestroData"))
            try:
                rsync_copy(maestro_local_path, maestro_server_path)
            except Exception as e:
                log.info("failed maestro processing %s", repr(e))
                self.has_error = True
            else:
                try:
                    shutil.rmtree(maestro_local_path, ignore_errors=False, onerror=rmtree_fix)
                except Exception as e:
                    log.info("cant remove local maestro %s", repr(e))
                    self.has_error = True
                else:
                    self.do_to_server_main()
        else:
            self.do_to_server_main()
        return None

    def do_to_server_main(self):
        keys_path = os.path.abspath(os.path.join(u_config['sync_path'], self.keys))
        diagnostics_path = os.path.abspath(os.path.join(keys_path, "diagnostics"))
        try:
            log.info("diagnostics processing")
            rsync_copy(diagnostics_path, m_config['rsync']['server'] + ":" + m_config['rsync']['keys_path'] + self.keys + "/")
        except Exception as e:
            log.info("failed rsync to server: %s", repr(e))
            self.has_error = True
        else:
            try:
                shutil.rmtree(keys_path, ignore_errors=False, onerror=rmtree_fix)
            except Exception as e:
                log.info("cant remove local keys path %s", repr(e))
                self.has_error = True
        return None

class MainWindow(Ui_MainForm):
    def to_work(self):
        _translate = QtCore.QCoreApplication.translate
        log.info("to work class")
        self.pushButton.setDown(True)
        self.pushButton_2.setEnabled(False)
        self.pushButton_3.setEnabled(False)
        self.pushButton_4.setEnabled(False)
        self.comboBox.setEnabled(False)
        cur_keys = str(self.comboBox.currentText())
        if not cur_keys:
            self.combobox_changed()
            self.pushButton.setDown(False)
            self.comboBox.setEnabled(True)
            return None
        for iter_keys in keys_locks_list:
            iter_lock_content = get_lock_content(iter_keys)
            if iter_lock_content is not None:
                log.info("try load json from iter lock")
                try:
                    iter_lock_json = json.loads(iter_lock_content.decode())
                    if not 'id' in iter_lock_json:
                        continue
                    if not 'username' in iter_lock_json:
                        continue
                    if iter_lock_json['id'] == u_config['id'] and iter_lock_json['username'] == u_config['username']:
                        self.combobox_changed()
                        self.label_2.setText(_translate("MainForm", "Уже в работе кейс {}".format(iter_keys)))
                        self.pushButton.setDown(False)
                        self.comboBox.setEnabled(True)
                        return None
                except Exception as e:
                    log.info("cant iterate %s", repr(e))
                    continue
        try:
            self.label_2.setText(_translate("MainForm", "Берем в работу: блокировка"))
            QtWidgets.qApp.processEvents()
            timestamp = int(time.time())
            lock = json.dumps(dict(
                id=u_config['id'],
                username=u_config['username'],
                timestamp=timestamp,
                surname=u_config['surname'],
                name=u_config['name'],
                patronymic=u_config['patronymic']
            ))
            if create_lock(cur_keys, lock):
                self.label_2.setText(_translate("MainForm", "Берем в работу: загрузка"))
                QtWidgets.qApp.processEvents()
                self.rsync_to_work = RsyncOperations(cur_keys, to_server=False, maestro=True)
                self.rsync_to_work.finished.connect(self.to_work_end)
                self.rsync_to_work.start()
            else:
                log.info('cant create lock in to work')
                raise ValueError("cant get lock")
        except Exception as e:
            self.label_2.setText(_translate("MainForm", "Ошибка взятия в работу"))
            log.info("to work error %s", repr(e))
        return None

    def to_work_end(self):
        _translate = QtCore.QCoreApplication.translate
        cur_keys = str(self.comboBox.currentText())
        if self.rsync_to_work.has_error:
            release_lock(cur_keys)
        temp_keys_locks_list = list_locks()
        global keys_locks_list
        if keys_locks_list and temp_keys_locks_list is None:
            log.info("keys_locks_list and not temp_keys_locks_list")
            pass
        else:
            log.info("temp_keys_locks_list to keys_locks_list")
            keys_locks_list = temp_keys_locks_list
        self.combobox_changed()
        if self.rsync_to_work.has_error:
            self.label_2.setText(_translate("MainForm", "Ошибка взятия в работу"))
        self.pushButton.setDown(False)
        self.comboBox.setEnabled(True)
        self.rsync_to_work.quit()
        return None

    def end_work(self):
        _translate = QtCore.QCoreApplication.translate
        self.pushButton.setEnabled(False)
        self.pushButton_2.setDown(True)
        self.pushButton_3.setEnabled(False)
        self.pushButton_4.setEnabled(False)
        self.comboBox.setEnabled(False)
        log.info("to_server class")
        cur_keys = str(self.comboBox.currentText())
        if not cur_keys:
            self.combobox_changed()
            self.pushButton_2.setDown(False)
            self.comboBox.setEnabled(True)
            return None
        try:
            self.label_2.setText(_translate("MainForm", "Вывод из работы"))
            QtWidgets.qApp.processEvents()
            self.rsync_end_work = RsyncOperations(cur_keys, to_server=True, maestro=True)
            self.rsync_end_work.finished.connect(self.end_work_end)
            self.rsync_end_work.start()
        except Exception as e:
            log.info("end work error %s", repr(e))
            self.label_2.setText(_translate("MainForm", "Ошибка вывода из работы"))
        return None

    def end_work_end(self):
        _translate = QtCore.QCoreApplication.translate
        if not self.rsync_end_work.has_error:
            cur_keys = str(self.comboBox.currentText())
            if release_lock(cur_keys):
                temp_keys_locks_list = list_locks()
                global keys_locks_list
                if keys_locks_list and temp_keys_locks_list is None:
                    log.info("keys_locks_list and not temp_keys_locks_list")
                    pass
                else:
                    log.info("temp_keys_locks_list to keys_locks_list")
                    keys_locks_list = temp_keys_locks_list
            else:
                self.combobox_changed()
                self.label_2.setText(_translate("MainForm", "Ошибка вывода из работы"))
        self.combobox_changed()
        if self.rsync_end_work.has_error:
            log.info("end work error")
            self.label_2.setText(_translate("MainForm", "Ошибка вывода из работы"))
        self.pushButton_2.setDown(False)
        self.comboBox.setEnabled(True)
        self.rsync_end_work.quit()
        return None


    def to_view(self):
        _translate = QtCore.QCoreApplication.translate
        self.pushButton.setEnabled(False)
        self.pushButton_2.setEnabled(False)
        self.pushButton_3.setDown(True)
        self.pushButton_4.setEnabled(False)
        self.comboBox.setEnabled(False)
        cur_keys = str(self.comboBox.currentText())
        if not cur_keys:
            self.combobox_changed()
            self.pushButton_3.setDown(False)
            self.comboBox.setEnabled(True)
            return None
        try:
            log.info("try get to view")
            self.label_4.setText(_translate("MainForm", "Загрузка для просмотра"))
            QtWidgets.qApp.processEvents()
            self.rsync_to_view = RsyncOperations(cur_keys, to_server=False, maestro=False)
            self.rsync_to_view.finished.connect(self.to_view_end)
            self.rsync_to_view.start()
        except Exception as e:
            log.info("get to view error %s", repr(e))
            self.label_4.setText(_translate("MainForm", "Ошибка загрузки для просмотра"))
        return None

    def to_view_end(self):
        _translate = QtCore.QCoreApplication.translate
        self.combobox_changed()
        if self.rsync_to_view.has_error:
            self.label_4.setText(_translate("MainForm", "Ошибка загрузки для просмотра"))
        self.pushButton_3.setDown(False)
        self.comboBox.setEnabled(True)
        self.rsync_to_view.quit()
        return None

    def end_view(self):
        _translate = QtCore.QCoreApplication.translate
        self.pushButton.setEnabled(False)
        self.pushButton_2.setEnabled(False)
        self.pushButton_3.setEnabled(False)
        self.pushButton_4.setDown(True)
        self.comboBox.setEnabled(False)
        cur_keys = str(self.comboBox.currentText())
        if not cur_keys:
            self.combobox_changed()
            self.pushButton_4.setDown(False)
            self.comboBox.setEnabled(True)
            return None
        rmpath = os.path.abspath(os.path.join(u_config['sync_path'], cur_keys))
        try:
            log.info("try end view %s", rmpath)
            self.label_4.setText(_translate("MainForm", "Завершение просмотра"))
            QtWidgets.qApp.processEvents()
            shutil.rmtree(rmpath, ignore_errors=False, onerror=rmtree_fix)
            self.combobox_changed()
        except Exception as e:
            log.info("end view error %s", repr(e))
            self.label_4.setText(_translate("MainForm", "Ошибка завершения просмотра"))
        self.pushButton_4.setDown(False)
        self.comboBox.setEnabled(True)
        return None

    def combobox_changed(self):
        _translate = QtCore.QCoreApplication.translate
        if not auth_info['success']:
            self.pushButton.setEnabled(False)
            self.pushButton_2.setEnabled(False)
            self.pushButton_3.setEnabled(False)
            self.pushButton_4.setEnabled(False)
            self.label_2.setText(_translate("MainForm", "Вход не выполнен"))
            self.label_3.setText(_translate("MainForm", " "))
            self.label_4.setText(_translate("MainForm", " "))
            return None
        cur_keys = str(self.comboBox.currentText())
        if not keys_list:
            self.pushButton.setEnabled(False)
            self.pushButton_2.setEnabled(False)
            self.pushButton_3.setEnabled(False)
            self.pushButton_4.setEnabled(False)
            self.label_2.setText(_translate("MainForm", "Нет связи с сервером"))
            self.label_3.setText(_translate("MainForm", " "))
            self.label_4.setText(_translate("MainForm", " "))
            return None
        if not cur_keys:
            self.pushButton.setEnabled(False)
            self.pushButton_2.setEnabled(False)
            self.pushButton_3.setEnabled(False)
            self.pushButton_4.setEnabled(False)
            self.label_2.setText(_translate("MainForm", "Не выбран"))
            self.label_3.setText(_translate("MainForm", " "))
            self.label_4.setText(_translate("MainForm", " "))
            return None
        if not cur_keys in keys_list:
            self.pushButton.setEnabled(False)
            self.pushButton_2.setEnabled(False)
            self.pushButton_3.setEnabled(False)
            self.pushButton_4.setEnabled(False)
            self.label_2.setText(_translate("MainForm", "Отсутствует на сервере"))
            self.label_3.setText(_translate("MainForm", " "))
            self.label_4.setText(_translate("MainForm", " "))
            return None
        if cur_keys in keys_locks_list:
            cur_lock_content = get_lock_content(cur_keys)
            if cur_lock_content is not None:
                try:
                    log.info("try load json from cur lock")
                    cur_lock_json = json.loads(cur_lock_content.decode())
                    if not cur_lock_json['id']:
                        self.pushButton.setEnabled(False)
                        self.pushButton_2.setEnabled(False)
                        self.pushButton_3.setEnabled(False)
                        self.pushButton_4.setEnabled(False)
                        self.label_2.setText(_translate("MainForm", "Ошибка 2:"))
                        self.label_3.setText(_translate("MainForm", "Попробуйте выбрать другой кейс"))
                        self.label_4.setText(_translate("MainForm", " "))
                        return None
                    if not cur_lock_json['username']:
                        self.pushButton.setEnabled(False)
                        self.pushButton_2.setEnabled(False)
                        self.pushButton_3.setEnabled(False)
                        self.pushButton_4.setEnabled(False)
                        self.label_2.setText(_translate("MainForm", "Ошибка 3:"))
                        self.label_3.setText(_translate("MainForm", "Попробуйте выбрать другой кейс"))
                        self.label_4.setText(_translate("MainForm", " "))
                        return None
                    if not cur_lock_json['timestamp']:
                        self.pushButton.setEnabled(False)
                        self.pushButton_2.setEnabled(False)
                        self.pushButton_3.setEnabled(False)
                        self.pushButton_4.setEnabled(False)
                        self.label_2.setText(_translate("MainForm", "Ошибка 4:"))
                        self.label_3.setText(_translate("MainForm", "Попробуйте выбрать другой кейс"))
                        self.label_4.setText(_translate("MainForm", " "))
                        return None
                    if cur_lock_json['id'] == u_config['id'] and cur_lock_json['username'] == u_config['username']:
                        h_timestamp = to_human_readable_ts(cur_lock_json['timestamp'])
                        self.pushButton.setEnabled(False)
                        self.pushButton_2.setEnabled(True)
                        self.pushButton_3.setEnabled(False)
                        self.pushButton_4.setEnabled(False)
                        self.label_2.setText(_translate("MainForm", "В работе локально:"))
                        self.label_3.setText(_translate("MainForm", "Время начала {}".format(h_timestamp)))
                        self.label_4.setText(_translate("MainForm", " "))
                        return None
                    # add id!= id or username != username

                    surname = str()
                    name = str()
                    patronymic = str()
                    if cur_lock_json['surname']:
                        surname = cur_lock_json['surname']
                    if cur_lock_json['name']:
                        name = cur_lock_json['name'][0]
                    if cur_lock_json['patronymic']:
                        patronymic = cur_lock_json['patronymic'][0]
                    fio = "{} {}.{}.".format(surname, name, patronymic)
                    h_timestamp = to_human_readable_ts(cur_lock_json['timestamp'])
                    self.pushButton.setEnabled(False)
                    self.pushButton_2.setEnabled(False)
                    if os.path.exists(os.path.abspath(os.path.join(u_config['sync_path'], cur_keys))):
                        self.pushButton_3.setEnabled(False)
                        self.pushButton_4.setEnabled(True)
                        self.label_4.setText(_translate("MainForm", "Просматривается локально"))
                    else:
                        self.pushButton_3.setEnabled(True)
                        self.pushButton_4.setEnabled(False)
                        self.label_4.setText(_translate("MainForm", "Не просматривается локально"))
                    self.label_2.setText(_translate("MainForm", "В работе:"))
                    self.label_3.setText(_translate("MainForm", "{} c {}".format(fio, h_timestamp)))
                    return None
                except Exception as e:
                    log.info("cant load json %s", repr(e))
                    self.pushButton.setEnabled(False)
                    self.pushButton_2.setEnabled(False)
                    self.pushButton_3.setEnabled(False)
                    self.pushButton_4.setEnabled(False)
                    self.label_2.setText(_translate("MainForm", "Ошибка 1:"))
                    self.label_3.setText(_translate("MainForm", "Попробуйте выбрать другой кейс"))
                    self.label_4.setText(_translate("MainForm", " "))
            else:
                self.pushButton.setEnabled(False)
                self.pushButton_2.setEnabled(False)
                self.pushButton_3.setEnabled(False)
                self.pushButton_4.setEnabled(False)
                self.label_2.setText(_translate("MainForm", " "))
                self.label_3.setText(_translate("MainForm", " "))
                self.label_4.setText(_translate("MainForm", " "))
            return None

        self.pushButton.setEnabled(True)
        self.pushButton_2.setEnabled(False)
        if os.path.exists(os.path.abspath(os.path.join(u_config['sync_path'], cur_keys))):
            self.pushButton_3.setEnabled(False)
            self.pushButton_4.setEnabled(True)
            self.label_4.setText(_translate("MainForm", "Просматривается локально"))
        else:
            self.pushButton_3.setEnabled(True)
            self.pushButton_4.setEnabled(False)
            self.label_4.setText(_translate("MainForm", "Не просматривается локально"))
        self.label_2.setText(_translate("MainForm", "Свободен"))
        self.label_3.setText(_translate("MainForm", " "))
        return None
    def comboupdate(self):
        if not auth_info['success']:
            self.comboBox.clear()
            return None
        if self.combo_items == keys_list:
            return None
        self.combo_items = keys_list
        self.comboBox.clear()
        self.comboBox.addItems(self.combo_items)
        return None

class SMainWindow(MainWindow):
    def __init__(self, MainWindow):
        # Be sure to call the super class method
        log.info("init main window")
        self.setupUi(MainWindow)
        self.combo_items = keys_list
        self.comboBox.addItems(self.combo_items)
        self.comboBox.setDuplicatesEnabled(False)
        self.comboBox.completer().setCompletionMode(QtWidgets.QCompleter.PopupCompletion)
        self.combobox_changed()
        self.connect_slots()
        log.info("init main window finished")


    def connect_slots(self):
        self.pushButton.clicked.connect(self.to_work)
        self.pushButton_2.clicked.connect(self.end_work)
        self.pushButton_3.clicked.connect(self.to_view)
        self.pushButton_4.clicked.connect(self.end_view)
        self.comboBox.currentTextChanged.connect(self.combobox_changed)
        self.comboBox.activated.connect(self.comboupdate)
        self.comboBox.editTextChanged.connect(self.comboupdate)
        return None

class SettingsWindow(Ui_SettingsForm):
    def login(self):
        log.info("settings login call")
        if auth_info['success']:
            self.do_unlogin()
        else:
            self.do_login()
        self.up_auth.auth_up.emit()
        self.auth_edited()
        return None
    def do_login(self):
        global auth_info
        login = str(self.lineEdit.text())
        password = str(self.lineEdit_2.text())
        auth_cred = dict(login=login, password=password)
        log.info("login %s password %s", login, password)
        log.info(auth_cred)
        try:
            auth_info = get_auth_info(auth_cred)
            init_auth_info()
        except Exception as e:
            log.info("cant make login call %s", repr(e))
        return None

    def do_unlogin(self):
        global auth_info
        auth_info = dict()
        auth_info['success'] = False
        init_auth_info()
        return None

    def save(self):
        log.info("save call")
        login = str(self.lineEdit.text())
        password = str(self.lineEdit_2.text())
        user_sync_path = str(self.lineEdit_3.text())
        user_config = dict(auth=dict())
        if login:
            user_config['auth']['login'] = login
        if password:
            user_config['auth']['password'] = password
        if user_sync_path:
            user_config['user_sync_path'] = user_sync_path
        log.info(user_config)
        user_config_path = os.path.abspath(os.path.expanduser(m_config['user_config_path']))
        log.info(user_config_path)
        try:
            with open(user_config_path, 'w') as f:
                json.dump(user_config, f)
                f.close()
        except Exception as e:
            log.info("cant save user config %s", repr(e))
        global u_config
        try:
            u_config['auth'] = dict()
            if login:
                u_config['auth']['login'] = login
            if password:
                u_config['auth']['password'] = password
            if user_sync_path:
                u_config['user_sync_path'] = user_sync_path
            init_sync_path()
        except Exception as e:
            log.info("cant update config %s", repr(e))
        self.update_fields()
        return None
    def cancel(self):
        self.update_fields()
        self.do_login()
        self.up_auth.auth_up.emit()
        self.auth_edited()
        return None
    def select_folder(self):
        return None
    def update_fields(self):
        log.info("update fields call")
        _translate = QtCore.QCoreApplication.translate
        self.pushButton_4.setEnabled(False)
        self.pushButton_2.setEnabled(False)
        self.lineEdit.clear()
        self.lineEdit_2.clear()
        self.lineEdit_3.clear()
        if not 'user_sync_path' in u_config:
            self.lineEdit_3.setPlaceholderText(_translate("SettingsForm", u_config['sync_path']))
        else:
            self.lineEdit_3.setText(_translate("SettingsForm", u_config['user_sync_path']))
        if 'auth' in u_config:
            if 'login' in u_config['auth']:
                self.lineEdit.setText(_translate("SettingsForm", u_config['auth']['login']))
            if 'password' in u_config['auth']:
                self.lineEdit_2.setText(_translate("SettingsForm", u_config['auth']['password']))
        self.auth_edited()
        log.info("update fields call end")
        return None
    def auth_edited(self):
        log.info("auth edited call")
        _translate = QtCore.QCoreApplication.translate
        if auth_info['success']:
            self.pushButton.setText(_translate("SettingsForm", "Выход"))
            self.lineEdit.setEnabled(False)
            self.lineEdit_2.setEnabled(False)
        else:
            self.pushButton.setText(_translate("SettingsForm", "Вход"))
            self.lineEdit.setEnabled(True)
            self.lineEdit_2.setEnabled(True)
        login = str(self.lineEdit.text())
        password = str(self.lineEdit_2.text())
        if login and password:
            self.pushButton.setEnabled(True)
        else:
            self.pushButton.setEnabled(False)
        self.check_change()
        log.info("auth edited call end")
        return None
    def check_change(self):
        log.info("check change call")
        self.pushButton_2.setEnabled(False)
        login = str(self.lineEdit.text())
        password = str(self.lineEdit_2.text())
        user_sync_path = str(self.lineEdit_3.text())
        if 'user_sync_path' in u_config:
            if u_config['user_sync_path'] != user_sync_path:
                self.pushButton_2.setEnabled(True)
        else:
            if user_sync_path:
                self.pushButton_2.setEnabled(True)
        if 'auth' in u_config:
            if 'login' in u_config['auth']:
                if u_config['auth']['login'] != login:
                    self.pushButton_2.setEnabled(True)
            else:
                if login:
                    self.pushButton_2.setEnabled(True)
            if 'password' in u_config['auth']:
                if u_config['auth']['password'] != password:
                    self.pushButton_2.setEnabled(True)
            else:
                if passord:
                    self.pushButton_2.setEnabled(True)
        else:
            if login or password:
                self.pushButton_2.setEnabled(True)
        log.info("check change call end")
        return None

class SSettingsWindow(SettingsWindow):

    def __init__(self, SettingsForm):
        log.info("init settings window")
        self.up_auth = Communicate()
        self.setupUi(SettingsForm)
        self.update_fields()
        self.connect_slots()
        log.info("init settings window finished")

    def connect_slots(self):
        self.pushButton.clicked.connect(self.login)
        self.pushButton_2.clicked.connect(self.save)
        self.pushButton_3.clicked.connect(self.cancel)
        self.pushButton_4.clicked.connect(self.select_folder)
        self.lineEdit.editingFinished.connect(self.auth_edited)
        self.lineEdit_2.editingFinished.connect(self.auth_edited)
        return None


class QWidgetHide(QtWidgets.QWidget):
    def __init__ (self):
        QtWidgets.QWidget.__init__(self)
        self.setWindowIcon(QtGui.QIcon("bin/fl_icon.png"))
        self.hide()

    def closeEvent(self, event):
        event.ignore()
        self.hide()

class TrayIcon(QtWidgets.QSystemTrayIcon):
    def __init__(self, mainw, settingsw, parent=None):
        log.info("init tray icon")
        QtWidgets.QSystemTrayIcon.__init__(self, parent)
        _translate = QtCore.QCoreApplication.translate
        self.mainw = mainw
        self.settingsw = settingsw
        self.mw = SMainWindow(self.mainw)
        self.sw = SSettingsWindow(self.settingsw)
        self.setIcon(QtGui.QIcon("bin/fl_icon.png"))
        self.keys_action = QtWidgets.QAction(_translate('TrayIcon', "Кейсы"), self)
        self.settings_action = QtWidgets.QAction(_translate('TrayIcon', "Настройки"), self)
        self.quit_action = QtWidgets.QAction(_translate('TrayIcon', "Выход"), self)
        self.keys_action.triggered.connect(self.mainw_show)
        self.settings_action.triggered.connect(self.settingsw.show)
        self.quit_action.triggered.connect(self.quit_app)
        self.tray_menu = QtWidgets.QMenu(parent)
        self.tray_menu.addAction(self.keys_action)
        self.tray_menu.addSeparator()
        self.tray_menu.addAction(self.settings_action)
        self.tray_menu.addSeparator()
        self.tray_menu.addAction(self.quit_action)
        self.setContextMenu(self.tray_menu)
        self.activated.connect(self.clicked_detect)
        self.sw.up_auth.auth_up.connect(self.update_auth)
        if not auth_info['success']:
            self.keys_action.setEnabled(False)
            self.settingsw.show()
        log.info("init tray icon finished")

    def mainw_show(self):
        self.mw.comboupdate()
        self.mainw.show()

    def update_auth(self):
        log.info("update_auth tray call")
        if auth_info['success']:
            self.keys_action.setEnabled(True)
        else:
            self.keys_action.setEnabled(False)
        self.mw.comboupdate()
        self.mw.combobox_changed()
        QtWidgets.qApp.processEvents()


    def quit_app(self):
        self.mainw.hide()
        self.settingsw.hide()
        QtWidgets.qApp.processEvents()
        QtWidgets.qApp.quit()

    def clicked_detect(self, reason):
        if reason == QtWidgets.QSystemTrayIcon.Trigger:
            if self.mainw.isVisible():
                self.mainw.hide()
            else:
                if not auth_info['success']:
                    self.settingsw.show()
                else:
                    self.mainw_show()

def main():
    """Main function."""
    try:
        """Parsing main and user configs, init some vars"""
        global workdir
        workdir = get_current_workdir()
        # init main config
        global m_config
        main_config_path = os.path.abspath(os.path.join(workdir, "fl_conf.json"))
        m_config = parse_main_config(main_config_path)

        # init logger
        load_logger(m_config['log'])
        log.info("=====start flexilignersync=====")

        # init user config
        global u_config
        user_config_path = os.path.abspath(os.path.expanduser(m_config['user_config_path']))
        u_config = parse_user_config(user_config_path)

        # init variables for rsync functions
        log.info("init rsync vars")
        global rsync_env
        rsync_env = os.environ.copy()
        rsync_path = os.path.join(workdir, "bin") + ";" + os.environ.get('PATH')
        log.info('init rsync path %s', rsync_path)
        rsync_env['PATH'] = rsync_path
        rsync_env['USERNAME'] = m_config['rsync']['server_username']
        global rsync_ssh_opts
        # create ssh key file
        ssh_key = SshKey()
        rsync_ssh_opts = '-o StrictHostKeyChecking=no -o GlobalKnownHostsFile=/dev/null -o UserKnownHostsFile=/dev/null -o HashKnownHosts=no -i {} -l {}'.format(
            convert_win_path(ssh_key.path), m_config['rsync']['server_username'])

        # init local directory where to sync from server
        init_sync_path()

        """init zookeeper connection"""
        global zk
        zk = init_kazoo_client(m_config['zookeeper'])
        global auth_info
        if 'auth' in u_config:
            auth_info = get_auth_info(u_config['auth'])
        else:
            auth_info = dict(success=False)
        log.info(auth_info)
        init_auth_info()
        """init async background operations"""
        # init keys list background updater
        keys_list_background_loop()

        # init keys locks list background updater
        keys_locks_list_background_loop()

        global global_keys
        global_keys = str()
        log.info("before init app")
        app = QtWidgets.QApplication(sys.argv)

        mwindow = QWidgetHide()
        swindow = QWidgetHide()
        tray = TrayIcon(mwindow, swindow)
        log.info("before show mwindow")
        tray.show()

        app.exec()

    except KeyboardInterrupt:
        log.info("exiting by keyboard interrupt")
        return True
    except Exception as e:
        log.info("unhandled exception %s", repr(e))
        return False
    except SystemExit as e:
        log.info("unhandled sys exit %s", repr(e))
        return True
    finally:
        deinit_kazoo_client(zk)
        log.info("setting threading_event")
        threading_event.set()
        for i in range(0, 6):
            active = threading.active_count()
            log.info("active %d", active)
            if active == 1:
                break
            log.info("sleeping 1 attempt %d", i)
            time.sleep(1)
        ssh_key.remove()
        log.info("stop flexilignersync")
        logging.shutdown()

if __name__ == "__main__":
    os._exit(int(not main()))
