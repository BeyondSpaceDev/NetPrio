import sys
import json
from enum import Enum
from collections import deque
from typing import Dict, Deque, Tuple, List, Set

from PySide6.QtCore import (
    Qt,
    QAbstractTableModel,
    QAbstractItemModel,
    QModelIndex,
    Signal,
    QObject,
    QPoint,
)
from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QTableView,
    QPushButton,
    QLabel,
    QFormLayout,
    QDoubleSpinBox,
    QStyledItemDelegate,
    QComboBox,
    QMenu,
    QSplitter,
    QToolTip,
    QCheckBox,
    QScrollArea,
    QGroupBox,
)
from PySide6.QtNetwork import QTcpSocket
from PySide6.QtGui import QPainter, QCursor, QPen, QColor
from PySide6.QtCharts import (
    QChart,
    QChartView,
    QLineSeries,
    QValueAxis,
)

PYSIDE_VERSION = "PySide6"

# ----------------------------------------------------------------------
# Enums & Datenstrukturen
# ----------------------------------------------------------------------
class PriorityLevel(Enum):
    HIGH = 1
    MEDIUM = 2
    LOW = 3
    UNSPECIFIED = 99

    @staticmethod
    def from_int(i: int) -> "PriorityLevel":
        for lvl in PriorityLevel:
            if lvl.value == i:
                return lvl
        return PriorityLevel.UNSPECIFIED

    def __str__(self) -> str:
        if self == PriorityLevel.HIGH:
            return "High"
        if self == PriorityLevel.MEDIUM:
            return "Medium"
        if self == PriorityLevel.LOW:
            return "Low"
        return "-"


class ProcessEntry:
    def __init__(
        self,
        pid: int,
        name: str,
        priority: PriorityLevel = PriorityLevel.UNSPECIFIED,
        down_kbps: float = 0.0,
        up_kbps: float = 0.0,
    ):
        self.pid = pid
        self.name = name
        self.priority = priority
        self.down_kbps = down_kbps
        self.up_kbps = up_kbps


# ----------------------------------------------------------------------
# TableModel
# ----------------------------------------------------------------------
class ProcessTableModel(QAbstractTableModel):
    COL_PID = 0
    COL_NAME = 1
    COL_PRIORITY = 2
    COL_DOWN = 3
    COL_UP = 4

    def __init__(self, processes=None, parent=None):
        super().__init__(parent)
        self._processes: list[ProcessEntry] = processes or []

    def rowCount(self, parent=QModelIndex()) -> int:
        return len(self._processes)

    def columnCount(self, parent=QModelIndex()) -> int:
        return 5

    def data(self, index: QModelIndex, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        proc = self._processes[index.row()]
        col = index.column()
        if role in (Qt.DisplayRole, Qt.EditRole):
            if col == self.COL_PID:
                return proc.pid
            elif col == self.COL_NAME:
                return proc.name
            elif col == self.COL_PRIORITY:
                return str(proc.priority)
            elif col == self.COL_DOWN:
                return f"{proc.down_kbps:.1f}"
            elif col == self.COL_UP:
                return f"{proc.up_kbps:.1f}"
        return None

    def headerData(self, section: int, orientation, role=Qt.DisplayRole):
        if role != Qt.DisplayRole:
            return None
        if orientation == Qt.Horizontal:
            if section == self.COL_PID:
                return "PID"
            if section == self.COL_NAME:
                return "Prozess"
            if section == self.COL_PRIORITY:
                return "Priorität"
            if section == self.COL_DOWN:
                return "Download (KB/s)"
            if section == self.COL_UP:
                return "Upload (KB/s)"
        return None

    def flags(self, index: QModelIndex):
        if not index.isValid():
            return Qt.NoItemFlags
        base = Qt.ItemIsSelectable | Qt.ItemIsEnabled
        if index.column() == self.COL_PRIORITY:
            return base | Qt.ItemIsEditable
        return base

    def setData(self, index: QModelIndex, value, role=Qt.EditRole):
        if not index.isValid() or role != Qt.EditRole:
            return False
        proc = self._processes[index.row()]
        col = index.column()
        if col == self.COL_PRIORITY:
            if isinstance(value, PriorityLevel):
                proc.priority = value
            elif isinstance(value, str):
                mapping = {
                    "High": PriorityLevel.HIGH,
                    "Medium": PriorityLevel.MEDIUM,
                    "Low": PriorityLevel.LOW,
                    "-": PriorityLevel.UNSPECIFIED,
                }
                proc.priority = mapping.get(value, PriorityLevel.UNSPECIFIED)
            else:
                return False
            self.dataChanged.emit(index, index, [Qt.DisplayRole, Qt.EditRole])
            return True
        return False

    def get_or_create_process(self, pid: int, name: str) -> ProcessEntry:
        for p in self._processes:
            if p.pid == pid:
                p.name = name
                return p
        p = ProcessEntry(pid, name)
        self.beginInsertRows(QModelIndex(), len(self._processes), len(self._processes))
        self._processes.append(p)
        self.endInsertRows()
        return p

    def get_process(self, row: int) -> ProcessEntry:
        return self._processes[row]

    def find_row_by_pid(self, pid: int) -> int:
        for i, p in enumerate(self._processes):
            if p.pid == pid:
                return i
        return -1

    def add_or_update_pid_priority(self, pid: int, priority: PriorityLevel, name: str = "<manual>"):
        row = self.find_row_by_pid(pid)
        if row == -1:
            self.beginInsertRows(QModelIndex(), len(self._processes), len(self._processes))
            self._processes.append(ProcessEntry(pid, name, priority))
            self.endInsertRows()
        else:
            self._processes[row].priority = priority
            idx = self.index(row, self.COL_PRIORITY)
            self.dataChanged.emit(idx, idx, [Qt.DisplayRole, Qt.EditRole])


# ----------------------------------------------------------------------
# Priority-Delegate (Combobox in Tabellen-Spalte)
# ----------------------------------------------------------------------
class PriorityDelegate(QStyledItemDelegate):
    def createEditor(self, parent, option, index):
        combo = QComboBox(parent)
        combo.addItem("-", PriorityLevel.UNSPECIFIED)
        combo.addItem("High", PriorityLevel.HIGH)
        combo.addItem("Medium", PriorityLevel.MEDIUM)
        combo.addItem("Low", PriorityLevel.LOW)
        return combo

    def setEditorData(self, editor: QComboBox, index: QModelIndex):
        text = index.data(Qt.DisplayRole)
        idx = editor.findText(text)
        if idx < 0:
            idx = 0
        editor.setCurrentIndex(idx)

    def setModelData(self, editor: QComboBox, model: QAbstractItemModel, index: QModelIndex):
        lvl = editor.currentData()
        model.setData(index, lvl, Qt.EditRole)


# ----------------------------------------------------------------------
# BackendClient: TCP + JSON
# ----------------------------------------------------------------------
class BackendClient(QObject):
    statsReceived = Signal(dict)
    connected = Signal()
    disconnected = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.socket = QTcpSocket(self)
        self.socket.readyRead.connect(self.on_ready_read)
        self.socket.connected.connect(self.connected)
        self.socket.disconnected.connect(self.disconnected)
        self._buffer = ""

    def connect_to_backend(self, host="127.0.0.1", port=5555):
        if self.socket.state() == QTcpSocket.ConnectedState:
            return
        self.socket.connectToHost(host, port)

    def on_ready_read(self):
        data = self.socket.readAll().data().decode("utf-8", errors="ignore")
        self._buffer += data
        while "\n" in self._buffer:
            line, self._buffer = self._buffer.split("\n", 1)
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("type") == "STATS":
                self.statsReceived.emit(obj)

    def send_json(self, obj: dict):
        if self.socket.state() == QTcpSocket.ConnectedState:
            line = json.dumps(obj) + "\n"
            self.socket.write(line.encode("utf-8"))
            self.socket.flush()


# ----------------------------------------------------------------------
# TimeSeries Store
# ----------------------------------------------------------------------
class TimeSeriesStore:
    def __init__(self, maxlen: int = 120):
        # maxlen = Sekunden (2 Minuten bei 1 Hz)
        self.maxlen = maxlen
        self.per_pid: Dict[int, Tuple[Deque[float], Deque[float], Deque[float]]] = {}

    def push_pid(self, pid: int, down: float, up: float):
        if pid not in self.per_pid:
            self.per_pid[pid] = (
                deque(maxlen=self.maxlen),
                deque(maxlen=self.maxlen),
                deque(maxlen=self.maxlen),
            )
        self.per_pid[pid][0].append(down)
        self.per_pid[pid][1].append(up)
        self.per_pid[pid][2].append(down + up)

    def get_pid(self, pid: int):
        return self.per_pid.get(pid)

    def all_pids(self) -> List[int]:
        return list(self.per_pid.keys())


# ----------------------------------------------------------------------
# Math helpers
# ----------------------------------------------------------------------
def ema(values: List[float], alpha: float = 0.25) -> List[float]:
    if not values:
        return []
    out = [values[0]]
    s = values[0]
    for v in values[1:]:
        s = alpha * v + (1.0 - alpha) * s
        out.append(s)
    return out


def percentile(values: List[float], p: float) -> float:
    if not values:
        return 0.0
    vals = sorted(values)
    if p <= 0:
        return vals[0]
    if p >= 100:
        return vals[-1]
    k = int(round((p / 100.0) * (len(vals) - 1)))
    return vals[max(0, min(len(vals) - 1, k))]


# ----------------------------------------------------------------------
# Chart Widget
# ----------------------------------------------------------------------
class MultiProcessChart(QWidget):
    """
    Pro PID zwei Serien:
    - faded: ältere Daten innerhalb des Fensters (Alpha niedrig)
    - recent: neueste Daten (Alpha hoch)

    X-Achse: Sekunden innerhalb des Fensters (rechts = "jetzt").
    """

    MIN_Y = 5.0
    WINDOW_SECONDS = 120
    RECENT_SECONDS = 30  # letzte 30s voll sichtbar, Rest faded

    def __init__(self, title: str, parent=None):
        super().__init__(parent)
        self.chart = QChart()
        self.chart.setTitle(title)
        self.chart.legend().hide()

        self.axis_x = QValueAxis()
        self.axis_y = QValueAxis()

        self.axis_x.setLabelFormat("%d")
        self.axis_x.setTitleText("Zeit (s) (rechts = jetzt)")
        self.axis_y.setTitleText("KB/s")

        self.chart.addAxis(self.axis_x, Qt.AlignBottom)
        self.chart.addAxis(self.axis_y, Qt.AlignLeft)

        self.view = QChartView(self.chart)
        self.view.setRenderHint(QPainter.Antialiasing)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.view)

        # pid -> (old_series, recent_series)
        self.pid_series: Dict[int, Tuple[QLineSeries, QLineSeries]] = {}
        self._last_ymax = self.MIN_Y

    def _make_pen(self, base_color: QColor, alpha: int) -> QPen:
        c = QColor(base_color)
        c.setAlpha(alpha)
        pen = QPen(c)
        pen.setWidth(2)
        return pen

    def ensure_pid_series(self, pid: int, label: str) -> Tuple[QLineSeries, QLineSeries]:
        if pid in self.pid_series:
            old_s, recent_s = self.pid_series[pid]
            if old_s.name() != label + " (old)":
                old_s.setName(label + " (old)")
            if recent_s.name() != label:
                recent_s.setName(label)
            return old_s, recent_s

        recent_s = QLineSeries()
        recent_s.setName(label)
        recent_s.setPointsVisible(True)

        old_s = QLineSeries()
        old_s.setName(label + " (old)")
        old_s.setPointsVisible(False)

        def on_hover(point, state, _series=recent_s):
            if not state:
                return
            QToolTip.showText(
                QCursor.pos(),
                f"{label}\n{point.y():.1f} KB/s @ t={int(point.x())}",
            )

        recent_s.hovered.connect(on_hover)

        self.chart.addSeries(old_s)
        self.chart.addSeries(recent_s)

        old_s.attachAxis(self.axis_x)
        old_s.attachAxis(self.axis_y)
        recent_s.attachAxis(self.axis_x)
        recent_s.attachAxis(self.axis_y)

        base_color = recent_s.pen().color()
        old_s.setPen(self._make_pen(base_color, alpha=70))
        recent_s.setPen(self._make_pen(base_color, alpha=255))

        old_s.setVisible(False)
        recent_s.setVisible(False)

        self.pid_series[pid] = (old_s, recent_s)
        return old_s, recent_s

    def set_pid_visible(self, pid: int, visible: bool):
        if pid in self.pid_series:
            old_s, recent_s = self.pid_series[pid]
            old_s.setVisible(visible)
            recent_s.setVisible(visible)

    def update_pid_data(self, pid: int, values):
        if pid not in self.pid_series:
            return

        old_s, recent_s = self.pid_series[pid]
        vals = ema(list(values), alpha=0.25)
        n = len(vals)
        if n == 0:
            old_s.clear()
            recent_s.clear()
            return

        # x: rechts = 0 (jetzt), links = -(n-1)
        xs = [i - (n - 1) for i in range(n)]

        recent_n = min(self.RECENT_SECONDS, n)
        split = n - recent_n

        old_points = [QPoint(xs[i], vals[i]) for i in range(split)]
        recent_points = [QPoint(xs[i], vals[i]) for i in range(split, n)]

        old_s.replace(old_points)
        recent_s.replace(recent_points)

    def autoscale(self, series_len: int, y_values_for_scale: List[float]):
        window = max(10, self.WINDOW_SECONDS)
        self.axis_x.setRange(-(window - 1), 0)

        if not y_values_for_scale:
            y_values_for_scale = [0.0]

        max_v = max(y_values_for_scale) if y_values_for_scale else 0.0
        p95 = percentile(y_values_for_scale, 95.0)
        target_ymax = max(self.MIN_Y, p95 * 1.25, max_v * 1.05)

        if target_ymax > self._last_ymax:
            self._last_ymax = target_ymax
        else:
            self._last_ymax = max(self.MIN_Y, self._last_ymax * 0.92 + target_ymax * 0.08)

        self.axis_y.setRange(0.0, self._last_ymax)


# ----------------------------------------------------------------------
# MainWindow
# ----------------------------------------------------------------------
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"NetPrio Monitor GUI ({PYSIDE_VERSION})")

        self.model = ProcessTableModel()
        self.backend = BackendClient(self)

        # 2 Minuten Verlauf (bei 1 Hz)
        self.store = TimeSeriesStore(maxlen=120)

        self.pid_checkboxes: Dict[int, QCheckBox] = {}
        self.visible_pids: Set[int] = set()

        self._setup_ui()

        self.backend.statsReceived.connect(self.on_stats_received)
        self.backend.connected.connect(self.on_backend_connected)
        self.backend.disconnected.connect(self.on_backend_disconnected)

        self.backend.connect_to_backend()

    def _setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)

        splitter = QSplitter(Qt.Horizontal, central)

        # LEFT
        left = QWidget()
        left_layout = QVBoxLayout(left)

        btn_layout = QHBoxLayout()
        self.btn_connect = QPushButton("Verbinden")
        self.btn_apply_profiles = QPushButton("Profile anwenden")
        self.btn_refresh_prios = QPushButton("Prioritäten senden")

        self.btn_connect.clicked.connect(self.on_connect_clicked)
        self.btn_apply_profiles.clicked.connect(self.on_apply_profiles)
        self.btn_refresh_prios.clicked.connect(self.push_priorities_to_backend)

        btn_layout.addWidget(self.btn_connect)
        btn_layout.addWidget(self.btn_apply_profiles)
        btn_layout.addWidget(self.btn_refresh_prios)
        btn_layout.addStretch()
        left_layout.addLayout(btn_layout)

        # Tabelle
        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setItemDelegateForColumn(ProcessTableModel.COL_PRIORITY, PriorityDelegate(self.table))
        self.table.setSelectionBehavior(QTableView.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.horizontalHeader().setStretchLastSection(True)
        left_layout.addWidget(self.table)

        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.on_table_context_menu)

        # Profile UI
        profile_box = QWidget()
        form = QFormLayout(profile_box)

        self.spin_high = QDoubleSpinBox()
        self.spin_high.setRange(0, 1_000_000)
        self.spin_high.setValue(60000.0)
        self.spin_high.setSuffix(" KB/s")

        self.spin_medium = QDoubleSpinBox()
        self.spin_medium.setRange(0, 1_000_000)
        self.spin_medium.setValue(30000.0)
        self.spin_medium.setSuffix(" KB/s")

        self.spin_low = QDoubleSpinBox()
        self.spin_low.setRange(0, 1_000_000)
        self.spin_low.setValue(10000.0)
        self.spin_low.setSuffix(" KB/s")

        form.addRow(QLabel("Profile (max KB/s pro Priorität):"))
        form.addRow("High:", self.spin_high)
        form.addRow("Medium:", self.spin_medium)
        form.addRow("Low:", self.spin_low)

        left_layout.addWidget(profile_box)

        splitter.addWidget(left)

        # RIGHT
        right_scroll = QScrollArea()
        right_scroll.setWidgetResizable(True)

        right = QWidget()
        right_layout = QVBoxLayout(right)

        self.total_proc_chart = MultiProcessChart("Gesamt-Auslastung nach Prozess (Down+Up)")
        self.total_proc_chart.setMinimumHeight(360)
        right_layout.addWidget(self.total_proc_chart)

        box = QGroupBox("Serien im Gesamtgraph (aktivieren zum Anzeigen)")
        box_layout = QVBoxLayout(box)

        btns = QHBoxLayout()
        self.btn_hide_all = QPushButton("Alle ausblenden")
        self.btn_show_top10 = QPushButton("Top 10 anzeigen")
        self.btn_hide_all.clicked.connect(self.hide_all_series)
        self.btn_show_top10.clicked.connect(self.show_top10_series)
        btns.addWidget(self.btn_hide_all)
        btns.addWidget(self.btn_show_top10)
        btns.addStretch(1)
        box_layout.addLayout(btns)

        self.chk_scroll = QScrollArea()
        self.chk_scroll.setWidgetResizable(True)

        self.chk_container = QWidget()
        self.chk_container_layout = QVBoxLayout(self.chk_container)
        self.chk_container_layout.addStretch(1)
        self.chk_scroll.setWidget(self.chk_container)
        self.chk_scroll.setMinimumHeight(280)

        box_layout.addWidget(self.chk_scroll)
        right_layout.addWidget(box)
        right_layout.addStretch(1)

        right_scroll.setWidget(right)
        splitter.addWidget(right_scroll)

        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)

        layout = QVBoxLayout(central)
        layout.addWidget(splitter)

        self.statusBar().showMessage("Nicht verbunden")

    # Backend events
    def on_backend_connected(self):
        self.statusBar().showMessage("Mit Backend verbunden")

    def on_backend_disconnected(self):
        self.statusBar().showMessage("Backend getrennt")

    def on_connect_clicked(self):
        self.backend.connect_to_backend()

    # Checkbox helpers
    def ensure_pid_checkbox(self, pid: int, name: str):
        if pid in self.pid_checkboxes:
            self.pid_checkboxes[pid].setText(f"{name} (PID {pid})")
            return

        chk = QCheckBox(f"{name} (PID {pid})")
        chk.setChecked(False)

        def on_toggle(state, _pid=pid):
            visible = bool(state)
            if visible:
                self.visible_pids.add(_pid)
            else:
                self.visible_pids.discard(_pid)
            self.total_proc_chart.set_pid_visible(_pid, visible)

        chk.stateChanged.connect(on_toggle)
        self.chk_container_layout.insertWidget(self.chk_container_layout.count() - 1, chk)
        self.pid_checkboxes[pid] = chk

    def hide_all_series(self):
        for _, chk in self.pid_checkboxes.items():
            chk.setChecked(False)

    def show_top10_series(self):
        items = []
        for row in range(self.model.rowCount()):
            p = self.model.get_process(row)
            items.append((p.down_kbps + p.up_kbps, p.pid))
        items.sort(reverse=True)
        top = set(pid for _, pid in items[:10])
        for pid, chk in self.pid_checkboxes.items():
            chk.setChecked(pid in top)

    # Stats update
    def on_stats_received(self, stats: dict):
        procs = stats.get("processes", [])
        seen_pids: Set[int] = set()

        scale_values: List[float] = []
        series_len = 0

        # 1) Updates aus STATS
        for p in procs:
            pid = int(p.get("pid"))
            seen_pids.add(pid)

            name = p.get("name", "<unknown>")
            prio_int = int(p.get("prio", 99))
            down = float(p.get("down_kbps", 0.0))
            up = float(p.get("up_kbps", 0.0))

            proc = self.model.get_or_create_process(pid, name)
            proc.priority = PriorityLevel.from_int(prio_int)
            proc.down_kbps = down
            proc.up_kbps = up

            self.store.push_pid(pid, down, up)
            self.ensure_pid_checkbox(pid, name)
            self.total_proc_chart.ensure_pid_series(pid, f"{name} (PID {pid})")

        # 2) fehlende PIDs -> 0 pushen (damit nichts einfriert)
        for pid in self.store.all_pids():
            if pid not in seen_pids:
                self.store.push_pid(pid, 0.0, 0.0)
                row = self.model.find_row_by_pid(pid)
                if row != -1:
                    proc = self.model.get_process(row)
                    proc.down_kbps = 0.0
                    proc.up_kbps = 0.0

        # 3) Chart updaten + Autoscale
        for pid in self.store.all_pids():
            data = self.store.get_pid(pid)
            if not data:
                continue
            combined = list(data[2])
            if not combined:
                continue

            series_len = max(series_len, len(combined))

            if pid in self.visible_pids:
                self.total_proc_chart.update_pid_data(pid, combined)

            tail = combined[-80:] if len(combined) > 80 else combined
            scale_values.extend(tail)

        # Tabelle refresh
        if self.model.rowCount() > 0:
            top_left = self.model.index(0, 0)
            bottom_right = self.model.index(self.model.rowCount() - 1, self.model.columnCount() - 1)
            self.model.dataChanged.emit(top_left, bottom_right, [Qt.DisplayRole])

        self.total_proc_chart.autoscale(series_len, scale_values)

    # Context menu
    def on_table_context_menu(self, pos):
        index = self.table.indexAt(pos)
        if not index.isValid():
            return

        row = index.row()
        proc = self.model.get_process(row)

        self.ensure_pid_checkbox(proc.pid, proc.name)
        chk = self.pid_checkboxes.get(proc.pid)

        menu = QMenu(self)

        toggle_text = "Im Gesamtgraph anzeigen" if chk and not chk.isChecked() else "Im Gesamtgraph ausblenden"
        act_toggle_total = menu.addAction(toggle_text)

        prio_menu = menu.addMenu("Priorität zuweisen")
        act_prio_high = prio_menu.addAction("High")
        act_prio_med = prio_menu.addAction("Medium")
        act_prio_low = prio_menu.addAction("Low")
        act_prio_reset = prio_menu.addAction("- (Zurücksetzen)")

        menu.addSeparator()
        act_show_top10 = menu.addAction("Top 10 anzeigen")
        act_hide_all = menu.addAction("Alle ausblenden")

        action = menu.exec(self.table.viewport().mapToGlobal(pos))

        if action == act_toggle_total:
            self.pid_checkboxes[proc.pid].setChecked(not self.pid_checkboxes[proc.pid].isChecked())
            return

        if action in (act_prio_high, act_prio_med, act_prio_low, act_prio_reset):
            if action == act_prio_high:
                new_prio = PriorityLevel.HIGH
            elif action == act_prio_med:
                new_prio = PriorityLevel.MEDIUM
            elif action == act_prio_low:
                new_prio = PriorityLevel.LOW
            else:
                new_prio = PriorityLevel.UNSPECIFIED

            self.model.add_or_update_pid_priority(proc.pid, new_prio, name=proc.name)
            self.push_priorities_to_backend()
            self.statusBar().showMessage(f"PID {proc.pid} Priorität: {new_prio}", 2500)
            return

        if action == act_show_top10:
            self.show_top10_series()
        elif action == act_hide_all:
            self.hide_all_series()

    # Commands
    def on_apply_profiles(self):
        high = self.spin_high.value()
        med = self.spin_medium.value()
        low = self.spin_low.value()

        msg = {
            "type": "SET_PROFILES",
            "profiles": {
                "high": {"min_kbps": 0, "max_kbps": high},
                "medium": {"min_kbps": 0, "max_kbps": med},
                "low": {"min_kbps": 0, "max_kbps": low},
            },
        }
        self.backend.send_json(msg)
        self.statusBar().showMessage(
            f"Profile gesendet: High={high:.0f}, Medium={med:.0f}, Low={low:.0f}",
            3000,
        )

    def push_priorities_to_backend(self):
        prios = []
        for row in range(self.model.rowCount()):
            p = self.model.get_process(row)
            prios.append({"pid": p.pid, "level": p.priority.value})
        msg = {"type": "SET_PRIORITIES", "priorities": prios}
        self.backend.send_json(msg)
        self.statusBar().showMessage("Prioritäten gesendet", 2000)


# ----------------------------------------------------------------------
# main
# ----------------------------------------------------------------------
def main():
    app = QApplication(sys.argv)
    win = MainWindow()
    win.resize(1400, 800)
    win.show()
    if hasattr(app, "exec"):
        sys.exit(app.exec())
    else:
        sys.exit(app.exec_())


if __name__ == "__main__":
    main()
