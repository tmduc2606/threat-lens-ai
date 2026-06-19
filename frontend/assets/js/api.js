(function () {
  const getBase = () => {
    const explicit =
      window.THREATLENS_API_BASE ||
      localStorage.getItem("threatlens_api_base");

    if (explicit) return explicit;

    if (
      window.location.hostname === "localhost" ||
      window.location.hostname === "127.0.0.1"
    ) {
      return "http://localhost:8000/api";
    }

    return "/api";
  };

  async function request(path, options = {}) {
    const base = getBase();
    const url = `${base}${path}`;

    const response = await fetch(url, {
      headers: {
        "Content-Type": "application/json",
        ...(options.headers || {}),
      },
      ...options,
    });

    const contentType = response.headers.get("content-type") || "";
    const data = contentType.includes("application/json")
      ? await response.json()
      : await response.text();

    if (!response.ok) {
      const message = typeof data === "string" ? data : data?.detail || response.statusText;
      throw new Error(message);
    }

    return data;
  }

  window.ThreatLensAPI = {
    getBase,
    request,
    get: (path) => request(path, { method: "GET" }),
    post: (path, body) =>
      request(path, { method: "POST", body: JSON.stringify(body) }),
  };
})();