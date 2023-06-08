package home

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"

	"github.com/AdguardTeam/AdGuardHome/internal/aghalg"
	"github.com/AdguardTeam/AdGuardHome/internal/aghhttp"
	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
)

// clientJSON is a common structure used by several handlers to deal with
// clients.  Some of the fields are only necessary in one or two handlers and
// are thus made pointers with an omitempty tag.
//
// TODO(a.garipov): Consider using nullbool and an optional string here?  Or
// split into several structs?
type clientJSON struct {
	// Disallowed, if non-nil and false, means that the client's IP is
	// allowed.  Otherwise, the IP is blocked.
	Disallowed *bool `json:"disallowed,omitempty"`

	// DisallowedRule is the rule due to which the client is disallowed.
	// If Disallowed is true and this string is empty, the client IP is
	// disallowed by the "allowed IP list", that is it is not included in
	// the allowlist.
	DisallowedRule *string `json:"disallowed_rule,omitempty"`

	WHOISInfo      *RuntimeClientWHOISInfo     `json:"whois_info,omitempty"`
	SafeSearchConf *filtering.SafeSearchConfig `json:"safe_search"`

	Name string `json:"name"`

	BlockedServices []string `json:"blocked_services"`
	IDs             []string `json:"ids"`
	Tags            []string `json:"tags"`
	Upstreams       []string `json:"upstreams"`

	FilteringEnabled    bool `json:"filtering_enabled"`
	ParentalEnabled     bool `json:"parental_enabled"`
	SafeBrowsingEnabled bool `json:"safebrowsing_enabled"`
	// Deprecated: use safeSearchConf.
	SafeSearchEnabled        bool `json:"safesearch_enabled"`
	UseGlobalBlockedServices bool `json:"use_global_blocked_services"`
	UseGlobalSettings        bool `json:"use_global_settings"`

	IgnoreQueryLog   aghalg.NullBool `json:"ignore_querylog"`
	IgnoreStatistics aghalg.NullBool `json:"ignore_statistics"`
}

type runtimeClientJSON struct {
	WHOISInfo *RuntimeClientWHOISInfo `json:"whois_info"`

	IP     netip.Addr   `json:"ip"`
	Name   string       `json:"name"`
	Source clientSource `json:"source"`
}

type clientListJSON struct {
	Clients        []*clientJSON       `json:"clients"`
	RuntimeClients []runtimeClientJSON `json:"auto_clients"`
	Tags           []string            `json:"supported_tags"`
}

// handleGetClients is the handler for GET /control/clients HTTP API.
func (clients *clientsContainer) handleGetClients(w http.ResponseWriter, r *http.Request) {
	data := clientListJSON{}

	clients.lock.Lock()
	defer clients.lock.Unlock()

	for _, c := range clients.list {
		cj := clientToJSON(c)
		data.Clients = append(data.Clients, cj)
	}

	for ip, rc := range clients.ipToRC {
		cj := runtimeClientJSON{
			WHOISInfo: rc.WHOISInfo,

			Name:   rc.Host,
			Source: rc.Source,
			IP:     ip,
		}

		data.RuntimeClients = append(data.RuntimeClients, cj)
	}

	data.Tags = clientTags

	_ = aghhttp.WriteJSONResponse(w, r, data)
}

// jsonToClient converts JSON object to Client object.
func (clients *clientsContainer) jsonToClient(cj clientJSON, prev *Client) (c *Client, err error) {
	var safeSearchConf filtering.SafeSearchConfig
	if cj.SafeSearchConf != nil {
		safeSearchConf = *cj.SafeSearchConf
	} else {
		// TODO(d.kolyshev): Remove after cleaning the deprecated
		// [clientJSON.SafeSearchEnabled] field.
		safeSearchConf = filtering.SafeSearchConfig{
			Enabled: cj.SafeSearchEnabled,
		}

		// Set default service flags for enabled safesearch.
		if safeSearchConf.Enabled {
			safeSearchConf.Bing = true
			safeSearchConf.DuckDuckGo = true
			safeSearchConf.Google = true
			safeSearchConf.Pixabay = true
			safeSearchConf.Yandex = true
			safeSearchConf.YouTube = true
		}
	}

	c = &Client{
		safeSearchConf: safeSearchConf,

		Name: cj.Name,

		IDs:             cj.IDs,
		Tags:            cj.Tags,
		BlockedServices: cj.BlockedServices,
		Upstreams:       cj.Upstreams,

		UseOwnSettings:        !cj.UseGlobalSettings,
		FilteringEnabled:      cj.FilteringEnabled,
		ParentalEnabled:       cj.ParentalEnabled,
		SafeBrowsingEnabled:   cj.SafeBrowsingEnabled,
		UseOwnBlockedServices: !cj.UseGlobalBlockedServices,
	}

	if cj.IgnoreQueryLog != aghalg.NBNull {
		c.IgnoreQueryLog = cj.IgnoreQueryLog == aghalg.NBTrue
	} else if prev != nil {
		c.IgnoreQueryLog = prev.IgnoreQueryLog
	}

	if cj.IgnoreStatistics != aghalg.NBNull {
		c.IgnoreStatistics = cj.IgnoreStatistics == aghalg.NBTrue
	} else if prev != nil {
		c.IgnoreStatistics = prev.IgnoreStatistics
	}

	if safeSearchConf.Enabled {
		err = c.setSafeSearch(
			safeSearchConf,
			clients.safeSearchCacheSize,
			clients.safeSearchCacheTTL,
		)
		if err != nil {
			return nil, fmt.Errorf("creating safesearch for client %q: %w", c.Name, err)
		}
	}

	return c, nil
}

// clientToJSON converts Client object to JSON.
func clientToJSON(c *Client) (cj *clientJSON) {
	// TODO(d.kolyshev): Remove after cleaning the deprecated
	// [clientJSON.SafeSearchEnabled] field.
	cloneVal := c.safeSearchConf
	safeSearchConf := &cloneVal

	return &clientJSON{
		Name:                c.Name,
		IDs:                 c.IDs,
		Tags:                c.Tags,
		UseGlobalSettings:   !c.UseOwnSettings,
		FilteringEnabled:    c.FilteringEnabled,
		ParentalEnabled:     c.ParentalEnabled,
		SafeSearchEnabled:   safeSearchConf.Enabled,
		SafeSearchConf:      safeSearchConf,
		SafeBrowsingEnabled: c.SafeBrowsingEnabled,

		UseGlobalBlockedServices: !c.UseOwnBlockedServices,
		BlockedServices:          c.BlockedServices,

		Upstreams: c.Upstreams,

		IgnoreQueryLog:   aghalg.BoolToNullBool(c.IgnoreQueryLog),
		IgnoreStatistics: aghalg.BoolToNullBool(c.IgnoreStatistics),
	}
}

// handleAddClient is the handler for POST /control/clients/add HTTP API.
func (clients *clientsContainer) handleAddClient(w http.ResponseWriter, r *http.Request) {
	cj := clientJSON{}
	err := json.NewDecoder(r.Body).Decode(&cj)
	if err != nil {
		aghhttp.Error(r, w, http.StatusBadRequest, "failed to process request body: %s", err)

		return
	}

	c, err := clients.jsonToClient(cj, nil)
	if err != nil {
		aghhttp.Error(r, w, http.StatusBadRequest, "%s", err)

		return
	}

	ok, err := clients.Add(c)
	if err != nil {
		aghhttp.Error(r, w, http.StatusBadRequest, "%s", err)

		return
	}

	if !ok {
		aghhttp.Error(r, w, http.StatusBadRequest, "Client already exists")

		return
	}

	onConfigModified()
}

// handleDelClient is the handler for POST /control/clients/delete HTTP API.
func (clients *clientsContainer) handleDelClient(w http.ResponseWriter, r *http.Request) {
	cj := clientJSON{}
	err := json.NewDecoder(r.Body).Decode(&cj)
	if err != nil {
		aghhttp.Error(r, w, http.StatusBadRequest, "failed to process request body: %s", err)

		return
	}

	if len(cj.Name) == 0 {
		aghhttp.Error(r, w, http.StatusBadRequest, "client's name must be non-empty")

		return
	}

	if !clients.Del(cj.Name) {
		aghhttp.Error(r, w, http.StatusBadRequest, "Client not found")

		return
	}

	onConfigModified()
}

type updateJSON struct {
	Name string     `json:"name"`
	Data clientJSON `json:"data"`
}

// handleUpdateClient is the handler for POST /control/clients/update HTTP API.
//
// TODO(s.chzhen):  Accept updated parameters instead of whole structure.
func (clients *clientsContainer) handleUpdateClient(w http.ResponseWriter, r *http.Request) {
	dj := updateJSON{}
	err := json.NewDecoder(r.Body).Decode(&dj)
	if err != nil {
		aghhttp.Error(r, w, http.StatusBadRequest, "failed to process request body: %s", err)

		return
	}

	if len(dj.Name) == 0 {
		aghhttp.Error(r, w, http.StatusBadRequest, "Invalid request")

		return
	}

	var prev *Client
	var ok bool

	func() {
		clients.lock.Lock()
		defer clients.lock.Unlock()

		prev, ok = clients.list[dj.Name]
	}()

	if !ok {
		aghhttp.Error(r, w, http.StatusBadRequest, "client not found")
	}

	c, err := clients.jsonToClient(dj.Data, prev)
	if err != nil {
		aghhttp.Error(r, w, http.StatusBadRequest, "%s", err)

		return
	}

	err = clients.Update(prev, c)
	if err != nil {
		aghhttp.Error(r, w, http.StatusBadRequest, "%s", err)

		return
	}

	onConfigModified()
}

// handleFindClient is the handler for GET /control/clients/find HTTP API.
func (clients *clientsContainer) handleFindClient(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	data := []map[string]*clientJSON{}
	for i := 0; i < len(q); i++ {
		idStr := q.Get(fmt.Sprintf("ip%d", i))
		if idStr == "" {
			break
		}

		ip, _ := netip.ParseAddr(idStr)
		c, ok := clients.Find(idStr)
		var cj *clientJSON
		if !ok {
			cj = clients.findRuntime(ip, idStr)
		} else {
			cj = clientToJSON(c)
			disallowed, rule := clients.dnsServer.IsBlockedClient(ip, idStr)
			cj.Disallowed, cj.DisallowedRule = &disallowed, &rule
		}

		data = append(data, map[string]*clientJSON{
			idStr: cj,
		})
	}

	_ = aghhttp.WriteJSONResponse(w, r, data)
}

// findRuntime looks up the IP in runtime and temporary storages, like
// /etc/hosts tables, DHCP leases, or blocklists.  cj is guaranteed to be
// non-nil.
func (clients *clientsContainer) findRuntime(ip netip.Addr, idStr string) (cj *clientJSON) {
	rc, ok := clients.findRuntimeClient(ip)
	if !ok {
		// It is still possible that the IP used to be in the runtime clients
		// list, but then the server was reloaded.  So, check the DNS server's
		// blocked IP list.
		//
		// See https://github.com/AdguardTeam/AdGuardHome/issues/2428.
		disallowed, rule := clients.dnsServer.IsBlockedClient(ip, idStr)
		cj = &clientJSON{
			IDs:            []string{idStr},
			Disallowed:     &disallowed,
			DisallowedRule: &rule,
			WHOISInfo:      &RuntimeClientWHOISInfo{},
		}

		return cj
	}

	cj = &clientJSON{
		Name:      rc.Host,
		IDs:       []string{idStr},
		WHOISInfo: rc.WHOISInfo,
	}

	disallowed, rule := clients.dnsServer.IsBlockedClient(ip, idStr)
	cj.Disallowed, cj.DisallowedRule = &disallowed, &rule

	return cj
}

// RegisterClientsHandlers registers HTTP handlers
func (clients *clientsContainer) registerWebHandlers() {
	httpRegister(http.MethodGet, "/control/clients", clients.handleGetClients)
	httpRegister(http.MethodPost, "/control/clients/add", clients.handleAddClient)
	httpRegister(http.MethodPost, "/control/clients/delete", clients.handleDelClient)
	httpRegister(http.MethodPost, "/control/clients/update", clients.handleUpdateClient)
	httpRegister(http.MethodGet, "/control/clients/find", clients.handleFindClient)
}
