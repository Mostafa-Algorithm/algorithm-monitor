#!/usr/bin/env python3
from algorithm.colors import *
from algorithm.banners import make_banner
from algorithm.os import get_user_permission, os
from algorithm.loading import Loading, LoadingStyle
from datetime import datetime
from collections import defaultdict, deque
import psutil, atexit, time, re, json, hashlib, threading, notify2

# Configuration Constants
CONFIG_FILE = "/opt/.monitor/config.json"
LOG_DIR = "/opt/.monitor/logs/"
MAX_LOG_SIZE = 10 * 1024 * 1024  # 10MB
LOG_RETENTION_DAYS = 30


class Notification:
  def __init__(self, app_name="AlgoMonitor"):
    self.app_name = app_name
    self.has_gui = self.check_gui_environment()
    self.active_notifications = {}
    self.notification_timeout = 5000

  def check_gui_environment(self):
    """More robust GUI environment detection"""
    dbus_attempts = [
      f'unix:path=/run/user/{os.getuid()}/bus',
      'unix:path=/var/run/dbus/system_bus_socket',
      'unix:abstract=/tmp/dbus-XXXXXXXXXX',
      'tcp:host=localhost,port=12434'
    ]

    for attempt in dbus_attempts:
      try:
        os.environ['DBUS_SESSION_BUS_ADDRESS'] = attempt
        import dbus
        bus = dbus.SessionBus() if 'session' in attempt else dbus.SystemBus()
        bus.list_names()  # Test connection
        notify2.init(self.app_name)
        return True
      except Exception as e:
        pass

    return False

  def show_notification(self, message, level, pid=None):
    """Show notification with proper action handling"""
    if not self.has_gui:
      return

    try:
      if pid in self.active_notifications:
        self._close_notification(pid)

      icon = {
          "ALERT": "dialog-warning",
          "WARNING": "security-high",
          "ERROR": "dialog-error"
        }.get(level, "dialog-information")

      notification = notify2.Notification(f"{self.app_name} {level.title()}", message, icon)
      notification.show()
      self.active_notifications[pid] = notification
    except Exception as e:
      self.has_gui = False
      print(f"[ERROR] Notification: {e}")

  def _close_notification(self, pid):
    """Close and cleanup notification"""
    if pid in self.active_notifications:
      try:
        notification = self.active_notifications[pid]
        if hasattr(notification, 'close'):
          notification.close()
      except:
        pass
      finally:
        del self.active_notifications[pid]

  def cleanup(self):
    """Cleanup all active notifications"""
    for pid in list(self.active_notifications.keys()):
      self._close_notification(pid)


class AlgoMonitor:
  def __init__(self):
    self.config = self.load_config()
    self.known_ports = set()
    self.known_procs = set()
    self.known_connections = set()
    self.known_files = set()
    self.trusted_processes = set(self.config['TRUSTED_SYSTEM_PROCESSES'])
    self.trusted_ports = set(self.config['TRUSTED_PORTS'].keys())
    self.reverse_shell_indicators = set(self.config['REVERSE_SHELL_INDICATORS'])
    self.suspicious_patterns = [re.compile(p, re.IGNORECASE) for p in self.config['SUSPICIOUS_PATTERNS']]
    self.suspicious_network_patterns = [re.compile(p, re.IGNORECASE) for p in self.config['SUSPICIOUS_NETWORK_PATTERNS']]
    self.process_behavior = defaultdict(deque)
    self.network_behavior = defaultdict(deque)
    self.file_hashes = {}
    self.loading = None
    self.notification_handler = Notification()
    self.running = True
    self.whitelist_established = False

    # Initialize directories
    os.makedirs(LOG_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)

    # Load baseline behavior
    self.establish_baseline()

  def load_config(self):
    """Load configuration from file or use defaults"""
    try:
      with open(CONFIG_FILE, 'r') as f:
        config = json.load(f)
        return config
    except FileNotFoundError:
      self.log("Config file not found.", "ERROR")
    except json.JSONDecodeError as e:
      self.log("Config file content.", "ERROR")
      print(e)
    exit()

  def save_config(self):
    """Save current configuration to file"""
    with open(CONFIG_FILE, 'w') as f:
      json.dump(self.config, f, indent=4)

  def establish_baseline(self):
    """Establish baseline behavior for processes and network"""
    # Get initial process list
    for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline']):
      try:
        self.known_procs.add(proc.info['pid'])
      except (psutil.NoSuchProcess, psutil.AccessDenied):
        continue

    # Get initial port list
    self.known_ports = set(get_open_ports())

    # Get initial network connections
    for conn in psutil.net_connections(kind='inet'):
      if conn.status == 'ESTABLISHED':
        self.known_connections.add((conn.laddr.ip, conn.laddr.port, conn.raddr.ip, conn.raddr.port))

    # Mark whitelist as established after initial scan
    self.whitelist_established = True

  def log(self, message, level="INFO", pid=None):
    """Handle alerts, notifications, and log messages with rotation and retention"""
    time_now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Log the alert
    log_file = os.path.join(LOG_DIR, f"{level.lower()}.log")

    # Rotate log if needed
    if os.path.exists(log_file) and os.path.getsize(log_file) > MAX_LOG_SIZE:
      rotated_file = f"{log_file}.{int(time.time())}"
      os.rename(log_file, rotated_file)

    # Write to log
    with open(log_file, 'a') as f:
      f.write(f"[{time_now}] {message}\n")

    # Print log to console
    color = red if level in ["ALERT", "ERROR"] else yellow if level == "WARNING" else blue
    print(f"{color}[{level}] {message}")

    # Send notification
    if level in ["ALERT"] or pid is not None:
      self.notification_handler.show_notification(message, level, pid)

    # Clean up old logs
    self.cleanup_logs()

  def cleanup_logs(self):
    """Remove logs older than retention period"""
    now = time.time()
    for filename in os.listdir(LOG_DIR):
      filepath = os.path.join(LOG_DIR, filename)
      if os.path.isfile(filepath):
        file_age = now - os.path.getmtime(filepath)
        if file_age > LOG_RETENTION_DAYS * 24 * 60 * 60:
          os.remove(filepath)

  def is_process_trusted(self, proc_info):
    """Check if a process is trusted"""
    name = proc_info.get('name', '').lower()
    cmdline = ' '.join(proc_info.get('cmdline') or []).lower()
    username = proc_info.get('username', '')

    # Kernel threads are always trusted
    if not cmdline and username == 'root' and any(name.startswith(k) for k in ['kworker', 'kthreadd', 'ksoftirqd']):
      return True

    # Check against trusted processes
    if name in self.trusted_processes:
      return True

    # Check if process path is in standard system directories
    try:
      proc = psutil.Process(proc_info['pid'])
      exe_path = proc.exe()
      if any(exe_path.startswith(path) for path in ['/bin/', '/sbin/', '/usr/bin/', '/usr/sbin/', '/lib/', '/lib64/']):
        return True
    except (psutil.NoSuchProcess, psutil.AccessDenied):
      pass

    return False

  def is_process_suspicious(self, proc_info):
    """Check if a process shows suspicious characteristics"""
    name = proc_info.get('name', '')
    cmdline = ' '.join(proc_info.get('cmdline') or [])
    username = proc_info.get('username', '')

    # Check for suspicious patterns in name or command line
    if any(pattern.search(name) or pattern.search(cmdline) for pattern in self.suspicious_patterns):
      return True

    # Check for processes running from unusual locations
    try:
      proc = psutil.Process(proc_info['pid'])
      exe_path = proc.exe()
      if '/tmp/' in exe_path or '/dev/shm/' in exe_path or '/var/tmp/' in exe_path:
        return True
      if not any(exe_path.startswith(path) for path in ['/bin/', '/sbin/', '/usr/bin/', '/usr/sbin/', '/opt/']):
        return True
    except (psutil.NoSuchProcess, psutil.AccessDenied):
      pass
    print('false: ', name)
    return False

  def monitor_processes(self):
    """Monitor running processes for suspicious activity"""
    while self.running:
      current_procs = {}

      # Get current processes
      for proc in psutil.process_iter(
          ['pid', 'name', 'username', 'cmdline', 'cpu_percent', 'memory_percent', 'connections', 'num_fds']):
        try:
          proc.info['children'] = proc.children()
          current_procs[proc.info['pid']] = proc.info

          # Check for new processes
          if proc.info['pid'] not in self.known_procs:
            self.process_new(proc.info)

          # Check process behavior
          self.check_process_behavior(proc.info)

        except (psutil.NoSuchProcess, psutil.AccessDenied):
          continue

      # Update known processes
      self.known_procs = set(current_procs.keys())

      time.sleep(5)

  def process_new(self, proc_info):
    """Handle newly spawned processes"""
    name = proc_info['name']
    pid = proc_info['pid']
    cmdline = ' '.join(proc_info['cmdline']) if proc_info['cmdline'] else ''
    username = proc_info['username']

    # Skip if we're still establishing the whitelist
    if not self.whitelist_established:
      self.log(f"Skipping new process detection: {name} (PID: {pid})")
      return

    if self.is_process_trusted(proc_info):
      self.log(f"Trusted process detected: {name} (PID: {pid}) - CMD: {cmdline}")
      return

    # Check for reverse shell characteristics
    if self.detect_reverse_shell(proc_info):
      self.log(f"Potential reverse shell detected: {name} (PID: {pid})", "ALERT", pid)
      try:
        p = psutil.Process(pid)
        p.terminate()
        self.log(f"Terminated potential reverse shell: {name} (PID: {pid})", "INFO", pid)
      except psutil.NoSuchProcess:
        self.log(f"Reverse shell does not exist: {name} (PID: {pid})", "INFO", pid)
      except psutil.AccessDenied:
        self.log(f"Access denied to reverse shell: {name} (PID: {pid})", "ALERT", pid)
      return

    # Check if process is suspicious
    if self.is_process_suspicious(proc_info):
      self.log(f"Suspicious process detected: {name} (PID: {pid}) - CMD: {cmdline}", "WARNING", pid)
      try:
        p = psutil.Process(pid)
        p.terminate()
        self.log(f"Terminated suspicious process: {name} (PID: {pid})", "INFO", pid)
      except psutil.NoSuchProcess:
        self.log(f"Suspicious process does not exist: {name} (PID: {pid})", "INFO", pid)
      except psutil.AccessDenied:
        self.log(f"Access denied to suspicious process: {name} (PID: {pid})", "ALERT", pid)
      return

    self.log(f"Unknown process detected: {name} (PID: {pid}) by {username} - CMD: {cmdline}", "WARNING")


  def detect_reverse_shell(self, proc_info):
    """Detect potential reverse shell characteristics"""
    cmdline = ' '.join(proc_info.get('cmdline') or [])
    name = proc_info.get('name', '')

    # Check command line for indicators
    if any(re.search(pattern, cmdline, re.IGNORECASE) for pattern in self.reverse_shell_indicators):
      return True

    # Check for network connections with suspicious patterns
    try:
      proc = psutil.Process(proc_info['pid'])
      for conn in proc.connections():
        if conn.status == 'ESTABLISHED':
          raddr = conn.raddr
          if raddr and any(pattern.search(raddr.ip) for pattern in self.suspicious_network_patterns):
            return True
    except (psutil.NoSuchProcess, psutil.AccessDenied):
      pass

    return False

  def check_process_behavior(self, proc_info):
    """Check for anomalous process behavior"""
    pid = proc_info['pid']
    name = proc_info['name']

    # Track process behavior
    behavior = {
      'cpu': proc_info['cpu_percent'],
      'memory': proc_info['memory_percent'],
      'children': len(proc_info['children']),
      'connections': len(proc_info['connections']),
      'file_handles': proc_info['num_fds']
    }

    # Add to behavior history (keep last 10 samples)
    self.process_behavior[pid].append(behavior)
    if len(self.process_behavior[pid]) > 10:
      self.process_behavior[pid].popleft()

    # Check thresholds
    thresholds = []
    if behavior['cpu'] > self.config['PROCESS_THRESHOLDS']['cpu_percent']:
      thresholds.append(f"CPU: {behavior['cpu']}%, Memory: {behavior['memory']}%")

    if behavior['memory'] > self.config['PROCESS_THRESHOLDS']['memory_percent']:
      thresholds.append(f"CPU: {behavior['cpu']}%, Memory: {behavior['memory']}%")

    if behavior['children'] > self.config['PROCESS_THRESHOLDS']['children']:
      thresholds.append(f"Children: {behavior['children']}")

    if behavior['connections'] > self.config['PROCESS_THRESHOLDS']['connections']:
      thresholds.append(f"Connections: {behavior['connections']}")

    if behavior['file_handles'] > self.config['PROCESS_THRESHOLDS']['file_handles']:
      thresholds.append(f"File handles: {behavior['file_handles']}")

    if thresholds:
      self.log(f"Anomalous behavior detected in {name} (PID: {pid}): " + ', '.join(thresholds), "WARNING")


  def monitor_network(self):
    """Monitor network connections and traffic"""
    while self.running:
      current_ports = set(get_open_ports())
      new_ports = current_ports - self.known_ports

      # Check for new ports
      for port in new_ports:
        self.check_new_port(port)

      # Update known ports
      self.known_ports = current_ports

      # Check established connections
      self.check_connections()

      time.sleep(5)

  def check_new_port(self, port):
    """Check newly opened ports"""
    if port not in self.trusted_ports:
      # Try to identify the process using the port
      proc_name = "unknown"
      proc_pid = None
      for conn in psutil.net_connections(kind='inet'):
        if conn.laddr.port == port and conn.status == 'LISTEN':
          try:
            proc = psutil.Process(conn.pid)
            proc_pid = conn.pid
            proc_name = proc.name()
          except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
          break

      self.log(f"Unauthorized port opened: {port} by {proc_name}", "ALERT", proc_pid)

  def check_connections(self):
    """Check network connections for suspicious activity"""
    current_connections = set()

    for conn in psutil.net_connections(kind='inet'):
      if conn.status == 'ESTABLISHED':
        conn_key = (conn.laddr.ip, conn.laddr.port, conn.raddr.ip, conn.raddr.port)
        current_connections.add(conn_key)

        # Check for new connections
        if conn_key not in self.known_connections:
          self.check_new_connection(conn)

    # Update known connections
    self.known_connections = current_connections

  def check_new_connection(self, conn):
    """Check newly established connections"""
    try:
      proc = psutil.Process(conn.pid)
      proc_name = proc.name()
      proc_cmd = ' '.join(proc.cmdline())
    except (psutil.NoSuchProcess, psutil.AccessDenied):
      proc_name = "unknown"
      proc_cmd = "unknown"

    remote_ip = conn.raddr.ip
    remote_port = conn.raddr.port

    if remote_ip in ["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888"]:
      return  # Skip Google DNS

    # Check for suspicious remote IPs or ports
    if any(pattern.search(remote_ip) for pattern in self.suspicious_network_patterns):
      self.log(f"Suspicious outgoing connection from {proc_name} (PID: {conn.pid}) "
               f"to {remote_ip}:{remote_port}, Command: {proc_cmd}", "ALERT", conn.pid)
      return

    # Check for connections to non-standard ports
    if not remote_ip.startswith(('192.168.', '10.', '172.16.')) and remote_ip != '127.0.0.1':
      if remote_port not in self.trusted_ports:
        self.log(f"Outgoing connection to non-standard port from {proc_name} (PID: {conn.pid}) "
                 f"to {remote_ip}:{remote_port}, Command: {proc_cmd}", "WARNING")

  def monitor_filesystem(self):
    """Monitor protected directories for changes"""
    while self.running:
      for directory in self.config['PROTECTED_DIRECTORIES']:
        if os.path.exists(directory):
          for root, dirs, files in os.walk(directory):
            for file in files:
              filepath = os.path.join(root, file)
              self.check_file_changes(filepath)

      time.sleep(60)  # Check every minute

  def check_file_changes(self, filepath):
    """Check for file modifications or suspicious changes"""
    try:
      # Get file stats
      stat = os.stat(filepath)

      # Check for suspicious file permissions
      # if stat.st_mode & 0o7777 != 0o755 and stat.st_mode & 0o7777 != 0o644:
      #   self.log(f"File with unusual permissions: {filepath} ({oct(stat.st_mode & 0o7777)})", "WARNING")

      # Calculate file hash
      current_hash = self.calculate_file_hash(filepath)

      # Check if file has changed
      if filepath in self.file_hashes:
        if self.file_hashes[filepath] != current_hash:
          self.log(f"File modified: {filepath}", "WARNING")
          self.file_hashes[filepath] = current_hash
      else:
        self.file_hashes[filepath] = current_hash

    except (PermissionError, FileNotFoundError):
      pass

  def calculate_file_hash(self, filepath):
    """Calculate SHA256 hash of a file"""
    sha256 = hashlib.sha256()
    try:
      with open(filepath, 'rb') as f:
        while True:
          data = f.read(65536)  # 64kb chunks
          if not data:
            break
          sha256.update(data)
      return sha256.hexdigest()
    except (PermissionError, FileNotFoundError):
      return ""

  def monitor_user_activity(self):
    """Monitor user logins and activity"""
    last_users = set()
    while self.running:
      current_users = set()

      # Get current logged in users
      for user in psutil.users():
        current_users.add((user.name, user.host, user.terminal))

        # Check for new logins
        if (user.name, user.host, user.terminal) not in last_users:
          self.log(f"User login detected: {user.name} from {user.host} on {user.terminal}")

      # Check for logouts
      for user in last_users - current_users:
        self.log(f"User logout detected: {user[0]} from {user[1]} on {user[2]}")

      last_users = current_users
      time.sleep(30)

  def start(self):
    """Start all monitoring threads"""
    self.loading = Loading(message="Monitoring", style=LoadingStyle.RADAR, use_thread=True, color='green')
    self.loading.start()

    # Start monitoring threads
    threads = [
      threading.Thread(target=self.monitor_processes),
      threading.Thread(target=self.monitor_network),
      threading.Thread(target=self.monitor_filesystem),
      threading.Thread(target=self.monitor_user_activity)
    ]

    for thread in threads:
      thread.daemon = True
      thread.start()

    try:
      while True:
        time.sleep(1)
    except KeyboardInterrupt:
      exit(0)

  def stop(self):
    """Stop all monitoring activities"""
    self.running = False
    if self.loading:
      self.loading.stop(reset + 'Monitoring stopped.')
    self.save_config()


def get_open_ports():
  """Get all open ports on the system"""
  connections = psutil.net_connections(kind='inet')
  open_ports = set(conn.laddr.port for conn in connections if conn.status == 'LISTEN')
  return open_ports


def main():
  try:
    if get_user_permission() == 0:
      global monitor
      make_banner('AlgoMonitor')
      monitor = AlgoMonitor()
      atexit.register(monitor.stop)
      monitor.start()
    else:
      print(red + '[-] Permission denied')
  except KeyboardInterrupt:
    pass
  # except Exception as e:
  #   print(red + f'[-] Exception: {e}')


if __name__ == '__main__':
  global monitor
  main()