import React, { useState, useEffect, useCallback, useMemo } from "react";
import io from "socket.io-client";

const socket = io(process.env.REACT_APP_API_BASE_URL);

function Login({ onLoginSuccess }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");

  const handleSubmit = (e) => {
    e.preventDefault();
    fetch(`${process.env.REACT_APP_API_BASE_URL}/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    })
      .then((res) => {
        if (!res.ok) throw new Error("Login failed");
        return res.json();
      })
      .then((data) => {
        sessionStorage.setItem("token", data.token);
        onLoginSuccess();
      })
      .catch((err) => setError(err.message));
  };

  return (
    <div style={{ maxWidth: "400px", margin: "auto", padding: "20px" }}>
      <h2>Admin Login</h2>
      {error && <p style={{ color: "red" }}>{error}</p>}
      <form onSubmit={handleSubmit}>
        <div style={{ marginBottom: "10px" }}>
          <label>Username: </label>
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
          />
        </div>
        <div style={{ marginBottom: "10px" }}>
          <label>Password: </label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
        </div>
        <button type="submit">Login</button>
      </form>
    </div>
  );
}

function LogViewer() {
  const [allLogs, setAllLogs] = useState([]);
  const [ignoredPaths, setIgnoredPaths] = useState([]);
  const [loading, setLoading] = useState(true);
  const [ignoredLoading, setIgnoredLoading] = useState(false);
  const [error, setError] = useState(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [currentPage, setCurrentPage] = useState(1);
  const [filterType, setFilterType] = useState("all");
  const logsPerPage = 10;

  const fetchLogs = useCallback(() => {
    setLoading(true);
    fetch(`${process.env.REACT_APP_API_BASE_URL}/logs`, {
      headers: {
        Authorization: `Bearer ${sessionStorage.getItem("token")}`,
      },
    })
      .then((response) => {
        if (!response.ok) throw new Error("Failed to fetch logs");
        return response.json();
      })
      .then((data) => {
        const sortedLogs = [...data.logs].sort((a, b) => b.id - a.id);
        setAllLogs(sortedLogs);
        setLoading(false);
      })
      .catch((err) => {
        setError(err.message);
        setLoading(false);
      });
  }, []);

const fetchIgnoredPaths = useCallback(() => {
  setIgnoredLoading(true);
  fetch(`${process.env.REACT_APP_API_BASE_URL}/ignored`, {
    headers: {
      Authorization: `Bearer ${sessionStorage.getItem("token")}`,
    },
  })
    .then((response) => {
      if (!response.ok) throw new Error("Failed to fetch ignored paths");
      return response.json();
    })
    .then((data) => {
      // Use a fallback in case data.ignored_paths is undefined
      setIgnoredPaths(data.ignored_paths || []);
      setIgnoredLoading(false);
    })
    .catch((err) => {
      setError(err.message);
      setIgnoredLoading(false);
    });
}, []);

  useEffect(() => {
    if (filterType === "ignored") {
      fetchIgnoredPaths();
    } else {
      fetchLogs();
    }
  }, [filterType, fetchLogs, fetchIgnoredPaths]);

  const clearLogs = () => {
    fetch(`${process.env.REACT_APP_API_BASE_URL}/logs/clear`, {
      method: "DELETE",
      headers: {
        Authorization: `Bearer ${sessionStorage.getItem("token")}`,
      },
    })
      .then((response) => {
        if (!response.ok) throw new Error("Failed to clear logs");
        setAllLogs([]);
      })
      .catch((err) => setError(err.message));
  };

  const handleSearch = (event) => {
    setSearchTerm(event.target.value.toLowerCase());
    setCurrentPage(1);
  };

  const addNewLog = useCallback((newLog) => {
    setAllLogs((prevLogs) => [newLog, ...prevLogs]);
  }, []);

  useEffect(() => {
    const handlers = {
      new_log: addNewLog,
      new_file_log: addNewLog,
      malicious_command_alert: addNewLog,
    };

    Object.entries(handlers).forEach(([event, handler]) => {
      socket.on(event, handler);
    });

    return () => {
      Object.entries(handlers).forEach(([event, handler]) => {
        socket.off(event, handler);
      });
    };
  }, [addNewLog]);

  const filteredLogs = useMemo(() => {
    return allLogs.filter((log) => {
      const matchesCategory =
        filterType === "all"
          ? true
          : filterType === "malicious"
          ? log.event_type.toLowerCase().includes("malicious")
          : filterType === "rm"
          ? log.event_type.toLowerCase().includes("rm")
          : filterType === "merged"
          ? log.event_type.toLowerCase().includes("merged")
          : filterType === "injection"
          ? log.event_type.toLowerCase().includes("injection")
          : filterType === "file_events"
          ? log.event_type.toLowerCase().includes("file")
          : true;

      const matchesSearch = Object.values(log)
        .join(" ")
        .toLowerCase()
        .includes(searchTerm);

      return matchesCategory && matchesSearch;
    });
  }, [allLogs, filterType, searchTerm]);

  const currentLogs = useMemo(() => {
    const start = (currentPage - 1) * logsPerPage;
    const end = start + logsPerPage;
    return filteredLogs.slice(start, end);
  }, [filteredLogs, currentPage]);

  const totalPages = Math.ceil(filteredLogs.length / logsPerPage);

  const goToNextPage = () => currentPage < totalPages && setCurrentPage((p) => p + 1);
  const goToPreviousPage = () => currentPage > 1 && setCurrentPage((p) => p - 1);
  const goToPage = (page) => setCurrentPage(page);

  const getEventColor = (eventType) => {
    if (!eventType) return "white";
    const lowerCaseEvent = eventType.toLowerCase();

    if (lowerCaseEvent.includes("malicious")) return "#f09ea8";
    if (lowerCaseEvent.includes("critical")) return "#ff6666";
    if (lowerCaseEvent.includes("warning")) return "#ffcc00";
    if (lowerCaseEvent.includes("file")) return "#cce5ff";

    return "white";
  };

  return (
    <div style={{ padding: "20px", fontFamily: "Arial, sans-serif" }}>
      <h1>Activity Logs (Live)</h1>
      {loading && filterType !== "ignored" && <p>Loading logs...</p>}
      {ignoredLoading && filterType === "ignored" && <p>Loading ignored paths...</p>}
      {error && (
        <div style={{ color: "red", marginBottom: "20px" }}>
          <p>Error: {error}</p>
          <button onClick={filterType === "ignored" ? fetchIgnoredPaths : fetchLogs}>Retry</button>
        </div>
      )}

      <div
        style={{
          marginBottom: "20px",
          display: "flex",
          gap: "10px",
          flexWrap: "wrap",
        }}
      >
        <select
          value={filterType}
          onChange={(e) => {
            setFilterType(e.target.value);
            setCurrentPage(1);
          }}
          style={{ padding: "8px", borderRadius: "4px" }}
        >
          <option value="all">All Logs</option>
          <option value="file_events">File Events</option>
          <option value="rm">RM Commands</option>
          <option value="merged">Merged Commands</option>
          <option value="injection">Command Injection</option>
          <option value="malicious">Malicious</option>
          <option value="ignored">Ignored Paths</option>
        </select>

        {filterType !== "ignored" && (
          <input
            type="text"
            placeholder="Search logs..."
            value={searchTerm}
            onChange={handleSearch}
            style={{ padding: "8px", flexGrow: 1, maxWidth: "400px" }}
          />
        )}

        {filterType !== "ignored" && (
          <button
            onClick={clearLogs}
            style={{
              padding: "8px",
              backgroundColor: "#dc3545",
              color: "white",
              border: "none",
              borderRadius: "4px",
              cursor: "pointer",
            }}
          >
            Clear Logs
          </button>
        )}
      </div>

      {filterType === "ignored" ? (
        <div>
          <h2>Ignored Paths</h2>
          {ignoredPaths.length === 0 ? (
            <p>No ignored paths yet.</p>
          ) : (
            <ul>
		{ignoredPaths.map((item, index) => (
		  <li key={index}>
 		   <strong>{item.ignored_path}</strong>
  		  <br />
    		Trigger Logs: {JSON.stringify(item.trigger_logs)}
  		</li>
		))}

            </ul>
          )}
        </div>
      ) : (
        <React.Fragment>
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr style={{ backgroundColor: "#f0f0f0" }}>
                  <th style={{ padding: "12px", border: "1px solid #ddd" }}>ID</th>
                  <th style={{ padding: "12px", border: "1px solid #ddd" }}>User</th>
                  <th style={{ padding: "12px", border: "1px solid #ddd" }}>Event Type</th>
                  <th style={{ padding: "12px", border: "1px solid #ddd" }}>Timestamp</th>
                  <th style={{ padding: "12px", border: "1px solid #ddd" }}>Data</th>
                </tr>
              </thead>
              <tbody>
                {currentLogs.map((log) => (
                  <tr key={log.id} style={{ backgroundColor: getEventColor(log.event_type), color: "black" }}>
                    <td style={{ padding: "12px", border: "1px solid #ddd" }}>{log.id}</td>
                    <td style={{ padding: "12px", border: "1px solid #ddd" }}>{log.user}</td>
                    <td style={{ padding: "12px", border: "1px solid #ddd" }}>{log.event_type}</td>
                    <td style={{ padding: "12px", border: "1px solid #ddd" }}>{log.timestamp}</td>
                    <td style={{ padding: "12px", border: "1px solid #ddd" }}>{log.data}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div
            style={{
              marginTop: "20px",
              display: "flex",
              flexWrap: "wrap",
              justifyContent: "center",
              gap: "8px",
            }}
          >
            <button
              onClick={goToPreviousPage}
              disabled={currentPage === 1}
              style={{
                padding: "8px 16px",
                backgroundColor: "#007bff",
                color: "white",
                border: "none",
                borderRadius: "4px",
                cursor: currentPage === 1 ? "not-allowed" : "pointer",
              }}
            >
              Previous
            </button>

            {Array.from({ length: totalPages }, (_, i) => i + 1).map((page) => (
              <button
                key={page}
                onClick={() => goToPage(page)}
                style={{
                  padding: "8px 12px",
                  backgroundColor: currentPage === page ? "#0056b3" : "#007bff",
                  color: "white",
                  border: "none",
                  borderRadius: "4px",
                  cursor: "pointer",
                }}
              >
                {page}
              </button>
            ))}

            <button
              onClick={goToNextPage}
              disabled={currentPage === totalPages}
              style={{
                padding: "8px 16px",
                backgroundColor: "#007bff",
                color: "white",
                border: "none",
                borderRadius: "4px",
                cursor: currentPage === totalPages ? "not-allowed" : "pointer",
              }}
            >
              Next
            </button>
          </div>
        </React.Fragment>
      )}
    </div>
  );
}

function MainApp() {
  const [isAuthenticated, setIsAuthenticated] = useState(!!sessionStorage.getItem("token"));

  return (
    <>
      {isAuthenticated ? <LogViewer /> : <Login onLoginSuccess={() => setIsAuthenticated(true)} />}
    </>
  );
}

export default MainApp;
