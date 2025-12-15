import sys
import json
from enum import Enum

# ----------------------------------------------------------------------
# Flexibler Import: zuerst PySide6 versuchen, dann PySide2
# ----------------------------------------------------------------------
try:
    from PySide6.QtCore import (
        Qt,
        QAbstractTableModel,
        QModelIndex,
        Signal,
        QObject,
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
        QLineEdit,
        QGroupBox,
    )
    from PySide6.QtNetwork import QTcpSocket
    PYSIDE_VERSION = "PySide6"
except ImportError:
    from PySide2.QtCore import (
        Qt,
        QAbstractTableModel,
        QModelIndex,
        Signal,
        QObject,
    )
    from PySide2.QtWidgets import (
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
        QLineEdit,
        QGroupBox,
    )
    from PySide2.QtNetwork import QTcpSocket
    PYSIDE_VERSION = "PySide2"


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
    def __init__(self, pid: int, name: str,
                 priority: PriorityLevel = PriorityLevel.UNSPECIFIED,
                 down_kbps: float = 0.0,
                 up_kbps: float = 0.0):
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

    # eigene Hilfsfunktionen

    def set_processes(self, procs: list[ProcessEntry]):
        self.beginResetModel()
        self._processes = procs
        self.endResetModel()

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
            # neuen Eintrag erzeugen
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

    def setModelData(self, editor: QComboBox, model: QAbstractTableModel, index: QModelIndex):
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
# MainWindow
# ----------------------------------------------------------------------

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle(f"NetPrio Monitor GUI ({PYSIDE_VERSION})")

        self.model = ProcessTableModel()
        self.backend = BackendClient(self)

        self._setup_ui()

        self.backend.statsReceived.connect(self.on_stats_received)
        self.backend.connected.connect(self.on_backend_connected)
        self.backend.disconnected.connect(self.on_backend_disconnected)

        # beim Start versuchen zu verbinden
        self.backend.connect_to_backend()

    # --------------------------- UI-Aufbau -----------------------------

    def _setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)

        # --- Obere Button-Leiste ---
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

        main_layout.addLayout(btn_layout)

        # --- PID-Priorität setzen (Input-Feld) ---
        pid_group = QGroupBox("Manuelle PID-Priorität")
        pid_layout = QHBoxLayout(pid_group)

        self.pid_input = QLineEdit()
        self.pid_input.setPlaceholderText("PID eingeben (z.B. 12345)")

        self.pid_prio_combo = QComboBox()
        self.pid_prio_combo.addItem("-", PriorityLevel.UNSPECIFIED)
        self.pid_prio_combo.addItem("High (1)", PriorityLevel.HIGH)
        self.pid_prio_combo.addItem("Medium (2)", PriorityLevel.MEDIUM)
        self.pid_prio_combo.addItem("Low (3)", PriorityLevel.LOW)

        self.btn_set_pid_prio = QPushButton("PID setzen")
        self.btn_set_pid_prio.clicked.connect(self.on_set_pid_priority)

        pid_layout.addWidget(QLabel("PID:"))
        pid_layout.addWidget(self.pid_input, 1)
        pid_layout.addWidget(QLabel("Priorität:"))
        pid_layout.addWidget(self.pid_prio_combo)
        pid_layout.addWidget(self.btn_set_pid_prio)

        main_layout.addWidget(pid_group)

        # --- Tabelle ---
        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setItemDelegateForColumn(ProcessTableModel.COL_PRIORITY, PriorityDelegate(self.table))
        self.table.setSelectionBehavior(QTableView.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.horizontalHeader().setStretchLastSection(True)
        main_layout.addWidget(self.table)

        # --- Profile (High / Medium / Low) ---
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

        main_layout.addWidget(profile_box)

        self.statusBar().showMessage("Nicht verbunden")

    # ------------------------ Backend-Events ---------------------------

    def on_backend_connected(self):
        self.statusBar().showMessage("Mit Backend verbunden")

    def on_backend_disconnected(self):
        self.statusBar().showMessage("Backend getrennt")

    def on_connect_clicked(self):
        self.backend.connect_to_backend()

    # ------------------------ Stats / Tabelle --------------------------

    def on_stats_received(self, stats: dict):
        procs = stats.get("processes", [])

        for p in procs:
            pid = p.get("pid")
            name = p.get("name", "<unknown>")
            prio_int = p.get("prio", 99)
            down = p.get("down_kbps", 0.0)
            up = p.get("up_kbps", 0.0)

            prio = PriorityLevel.from_int(prio_int)

            proc = self.model.get_or_create_process(pid, name)
            proc.priority = prio
            proc.down_kbps = down
            proc.up_kbps = up

        if self.model.rowCount() > 0:
            top_left = self.model.index(0, 0)
            bottom_right = self.model.index(
                self.model.rowCount() - 1,
                self.model.columnCount() - 1
            )
            self.model.dataChanged.emit(top_left, bottom_right, [Qt.DisplayRole])

    # -------------------- Profile / Prioritäten senden -----------------

    def on_apply_profiles(self):
        high = self.spin_high.value()
        med = self.spin_medium.value()
        low = self.spin_low.value()

        msg = {
            "type": "SET_PROFILES",
            "profiles": {
                "high":   {"min_kbps": 0, "max_kbps": high},
                "medium": {"min_kbps": 0, "max_kbps": med},
                "low":    {"min_kbps": 0, "max_kbps": low},
            }
        }
        self.backend.send_json(msg)
        self.statusBar().showMessage(
            f"Profile gesendet: High={high:.0f}, Medium={med:.0f}, Low={low:.0f}",
            3000
        )

    def push_priorities_to_backend(self):
        prios = []
        for row in range(self.model.rowCount()):
            p = self.model.get_process(row)
            prios.append({"pid": p.pid, "level": p.priority.value})

        msg = {"type": "SET_PRIORITIES", "priorities": prios}
        self.backend.send_json(msg)
        self.statusBar().showMessage("Prioritäten gesendet", 2000)

    # -------------------- Manuelle PID-Priorität -----------------------

    def on_set_pid_priority(self):
        text = self.pid_input.text().strip()
        if not text.isdigit():
            self.statusBar().showMessage("Ungültige PID", 3000)
            return

        pid = int(text)
        prio = self.pid_prio_combo.currentData()
        if prio is None:
            prio = PriorityLevel.UNSPECIFIED

        # im Model eintragen/aktualisieren
        self.model.add_or_update_pid_priority(pid, prio, name="<manual>")

        # komplett an Backend senden
        self.push_priorities_to_backend()

        self.statusBar().showMessage(
            f"PID {pid} auf Priorität {prio.name} gesetzt",
            3000
        )


# ----------------------------------------------------------------------
# main
# ----------------------------------------------------------------------

def main():
    app = QApplication(sys.argv)
    win = MainWindow()
    win.resize(900, 600)
    win.show()

    # PySide6: exec(), PySide2: exec_()
    if hasattr(app, "exec"):
        sys.exit(app.exec())
    else:
        sys.exit(app.exec_())


if __name__ == "__main__":
    main()
