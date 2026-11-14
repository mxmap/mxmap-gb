/* map-security.js — security map logic (SPF + DMARC) for unified DACH view */

// Anpassung an mehr und generischen (Farbe durch Anzahl geprägt) Kategorien notwendig
var SEC_COLOR_SCHEMES = {
  default: {
    
    '6/6':       '#04ff92',
    '5/6':        '#04ff1d',
    '4/6':       '#9cfc01',
    '3/6':       '#dcfd06',
    '2/6':      '#ffe600',
    '1/6':       '#ffa60d',
    '0/6':       '#fe2815',
    'no-data': '#BFBFBF',
    lake: '#89B3D6',
  },
  colorblind: {
    '6/6':       '#04ff92',
    '5/6':        '#04ff1d',
    '4/6':       '#9cfc01',
    '3/6':       '#dcfd06',
    '2/6':      '#ffe600',
    '1/6':       '#ffa60d',
    '0/6':       '#fe2815',
    'no-data': '#BFBFBF',
    lake: '#89B3D6'
  }
};
var SEC_COLORS = SEC_COLOR_SCHEMES.default;
var SEC_GRAY = '#BFBFBF';

// Muss generischer werden
function securityCategoryDMARC(m) {
  var antiSpoofing = m && m.aggDomainAntiSpoofing;
  var metadata = antiSpoofing && antiSpoofing.aggDomainAntiSpoofingMetadata;
  var dmarcResult = antiSpoofing && antiSpoofing.aggDmarcResult;

  // 1. Basis-Checks
  if (!metadata || !metadata.isValid || !dmarcResult || !dmarcResult.generalDMARCData) {
    return 'no-data';
  }

  var general = dmarcResult.generalDMARCData;
  if (general.errorType != null) return 'error';
  if (!general.hasPolicy) return 'nodmarc';

  var tags = dmarcResult.dmarcTagValues;
  var reporting = dmarcResult.aggDmarcReportingData;
  if (!tags || !reporting) return 'no-data';

  // 2. Werte normalisieren & Typen sauber konvertieren (String -> Number / Lowercase)
  var p = (tags.p || '').toLowerCase();
  var sp = (tags.sp || p).toLowerCase(); // sp erbt laut RFC von p, wenn nicht explizit gesetzt
  var np = (tags.np || sp).toLowerCase();
  var t = (tags.t || 'n').toLowerCase();
  
  // Wichtig für JS: pct kommt als String "100" -> als Integer parsen (Default 100)
  var pct = tags.pct != null ? parseInt(tags.pct, 10) : 100;
  if (isNaN(pct)) pct = 100;

  // Suffix über aggDmarcReportingData bestimmen
  var reportCount = parseInt(reporting.reportDomainCount, 10) || 0;
  var suffix = reportCount > 0 ? '_reporting' : '';

  // -------------------------------------------------------------
  // 3. Einstufung nach Sicherheitslevel
  // -------------------------------------------------------------

  // STUFE 1: 'none'
  // Wenn eine der Policies 'none' ist ODER pct == 0 ODER Testmodus aktiv ('y')
  if ((p === 'none' || sp === 'none' || np === 'none' ) || 
  ((pct === 0 || t === 'y') && !( p === 'reject' || sp === 'reject' || np === 'reject'))) {
    return 'none' + suffix;
  }

  // STUFE 4: 'fullreject'
  // Alle Policies auf 'reject', 100% Durchsetzung und kein Testmodus
  var allReject = (p === 'reject' && sp === 'reject' && np === 'reject');
  if (allReject && pct === 100) {
    return 'fullreject' + suffix;
  }

  // STUFE 3: 'quarantine'
  // Entweder durchgehend mindestens 'quarantine' bei 100% ODER reject mit reduzierter Rate
  var allQuarantineOrBetter = (p === 'quarantine' || p === 'reject') &&
                              (sp === 'quarantine' || sp === 'reject') &&
                              (np === 'quarantine' || np === 'reject');

  if (allReject && pct < 100) {
    return 'quarantine' + suffix;
  }
  if (allQuarantineOrBetter && pct === 100) {
    return 'quarantine' + suffix;
  }

  // STUFE 2: 'partly'
  // Alles dazwischen (z. B. quarantine mit pct < 100 oder abweichende Subdomain-Regeln)
  return 'partly' + suffix;
}


function securityCategoryDANE(m) {
  var dataTransport = m && m.aggDomainDataTransport;
  var metadata = dataTransport && dataTransport.aggDataTransportMetadata;
  var daneResult = dataTransport && dataTransport.daneResult;

  // 1. Basis-Checks
  if (!metadata || !metadata.isValid || !daneResult) {
    return 'no-data';
  }

  if (daneResult.hasValidDaneAllMta) {return 'validdane_all_mx'};
  if (daneResult.hasValidDaneAtLeastOneMta) { return  'validdane_atleastone_mx'};
  if( daneResult.atLeastOneMtaSupportsDane) {return 'dane_atleastone_mx'};
  if(!daneResult.hasValidDaneAllMta && !daneResult.hasValidDaneAtLeastOneMta && !daneResult.atLeastOneMtaSupportsDane) {return 'nodane' };
  
  return 'no-data';
}

// Muss generischer werden
function securityCategorySpf(m) {


  var antiSpoofing = m && m.aggDomainAntiSpoofing;
  var metadata = antiSpoofing && antiSpoofing.aggDomainAntiSpoofingMetadata;
  var spfResult = antiSpoofing && antiSpoofing.aggSpfResult && antiSpoofing.aggSpfResult.spfGeneralData;
  if (spfResult && spfResult.errorType && spfResult.errorType.startsWith("An SPF record does not exist")) return 'nospf';
  if (!metadata || !metadata.isValid || !spfResult) return 'no-data';

  if (spfResult.errorType && !spfResult.valid) return 'error';
  
  if (metadata.isvalid && !spfResult.valid) return 'error';

  if (spfResult.allQualifier == "softfail") return 'softfail';
  if (spfResult.allQualifier == "fail") return 'fail';
  if (spfResult.allQualifier == "pass" || spfResult.allQualifier == "neutral") return 'passneutral';
  
  return 'no-data';


}


function securityCategoryTlsCert(m) {
  var dataTransport = m && m.aggDomainDataTransport;
  var metadata = dataTransport && dataTransport.aggDataTransportMetadata;
  var tlsCertData = dataTransport && dataTransport.tlsCertData;

  // 1. Basis-Checks
  if (!metadata || !metadata.isValid || !tlsCertData) {
    return 'no-data';
  }

  if (tlsCertData.allMxValidTlsResult) { return  'valid_starttls_all'};
  if (tlsCertData.atLeastOneMxValidTlsResult) {return 'valid_starttls_atleastonemx'};
  if( !tlsCertData.allMxValidTlsResult && !tlsCertData.atLeastOneMxValidTlsResult) {return 'error_starttls'};
  
  return 'no-data';
}


function securityCategoryDNSSEC(m) {
  var dataTransport = m && m.aggDomainDataTransport;
  var metadata = dataTransport && dataTransport.aggDataTransportMetadata;
  var dnssecResult = dataTransport && dataTransport.dnssecResult;

  // 1. Basis-Checks
  if (!metadata || !metadata.isValid || !dnssecResult) {
    return 'no-data';
  }

  if (dnssecResult.domainDNSSEC && dnssecResult.mxAllDNSSEC) {return 'dnssec_full'};
  if (dnssecResult.domainDNSSEC && !dnssecResult.mxAllDNSSEC) { return  'dnssec_domain'};
  if (!dnssecResult.domainDNSSEC && dnssecResult.mxAllDNSSEC) { return  'dnssec_allmx'};
  if(!dnssecResult.domainDNSSEC && !dnssecResult.mxAllDNSSEC && dnssecResult.mxAtLeastOneDNSSEC) {return 'dnssec_atleastonemx'};
  if(!dnssecResult.domainDNSSEC && !dnssecResult.mxAllDNSSEC && !dnssecResult.mxAtLeastOneDNSSEC) { return 'nodnssec'};

  return 'no-data';
}


function securityCategoryMtaSts(m) {
  var dataTransport = m && m.aggDomainDataTransport;
  var metadata = dataTransport && dataTransport.aggDataTransportMetadata;
  var mtaStsData = dataTransport && dataTransport.mtaStsData;

  // 1. Basis-Checks
  if (!metadata || !metadata.isValid || metadata.invalidMxCount > 0 || !metadata.isValid || !mtaStsData) {
    return 'no-data';
  }

  if(!mtaStsData.usesMtaSts) {
    return 'no_mtasts';
  }

  if(mtaStsData.generalErrorType) {
    return 'no-data';
  }

  if(mtaStsData.usesMtaSts && mtaStsData.policy) {

    var mtaStsPolicyMode = mtaStsData.policy.mode
    if (mtaStsPolicyMode === "enforce") {return 'mtasts_enforce'};
    if (mtaStsPolicyMode === "testing") { return  'mtasts_testing'};
    if (mtaStsPolicyMode === "none") {return 'mtasts_none'};
  }
  return 'no-data';
}


function securityCategory(m) {


  var count  = 0
  var spfResult = securityCategorySpf(m)
  var dmarcResult = securityCategoryDMARC(m)

  var dnssecResult = securityCategoryDNSSEC(m)

  var daneResult = securityCategoryDANE(m)
  var mtaStsResult = securityCategoryMtaSts(m)
  var tlsCertResult = securityCategoryTlsCert(m)

  if(spfResult === "no-data" || dmarcResult === "no-data" || dnssecResult === "no-data" 
    || daneResult === "no-data" || mtaStsResult === "no-data" || tlsCertResult === "no-data"
  ) { return "no-data"}


  if( "fail" === spfResult) {
    count ++;
  }

  if( "fullreject_reporting" === dmarcResult) {
    count ++;
  }

  if("dnssec_full" == dnssecResult ) {
    count ++;
  }


  if("validdane_all_mx" == daneResult  ) {
    count ++;
  }


  if("mtasts_enforce" == mtaStsResult) {
    count ++;
  }

  if("valid_starttls_all" == tlsCertResult) {
    count++;
  }

  return `${count}/6`;
}



function getErrorMessage(m) {

  var count  = 0
  var spfResult = securityCategorySpf(m)
  var dmarcResult = securityCategoryDMARC(m)

  var dnssecResult = securityCategoryDNSSEC(m)

  var daneResult = securityCategoryDANE(m)
  var mtaStsResult = securityCategoryMtaSts(m)
  var tlsCertResult = securityCategoryTlsCert(m)


  if(spfResult === "no-data" || dmarcResult === "no-data" || dnssecResult === "no-data" 
    || daneResult === "no-data" || mtaStsResult === "no-data" || tlsCertResult === "no-data"
  ) { return "no-data"}

  var result = "<strong>Correct configured measures:</strong>"

  if( "fail" === spfResult) {
    result += "<br>SPF: fail"
    count++
  }

  if( "fullreject_reporting" === dmarcResult) {
    result += "<br>DMARC: reject & reporting"
    count++
  }

  if("dnssec_full" == dnssecResult ) {
    result += "<br>DNSSEC domain and mta zone"
    count++
  }


  if("validdane_all_mx" == daneResult  ) {
    result += "<br>DANE for all mta"
    count++
  }


  if("mtasts_enforce" == mtaStsResult) {
    result += "<br>MTA-STS enforced"
    count++
  }

  if("valid_starttls_all" == tlsCertResult) {
    result += "<br>STARTTLS supported by all MTA with valid cert for TLS 1.2 or 1.3"
    count++
  }

  result += `<br><strong>Sum:${count}/6 </strong>`;

  return result;

}

function getRecord(m) {
  return "no record"
}


function getSecurityColor(m) {
  var cat = securityCategory(m);
  return SEC_COLORS[cat] || SEC_GRAY;
}

/*
function spfLabel(m) {
  
  if (!m.aggDomainAntiSpoofing.aggSpfResult) return { text: 'Missing', cls: 'sec-missing' };
  var spfResult = m.aggDomainAntiSpoofing.aggSpfResult.spfGeneralData;
  if (m.aggDomainAntiSpoofing.aggDomainAntiSpoofingMetadata.isValid ) return { text: 'Invalid', cls: 'sec-missing' };
  if (!spfResult.valid ) return { text: 'Error', cls: 'sec-missing' };
  
  if (spfResult.allQualifier == "softfail") return { text: 'Softfail', cls: 'sec-good' };
  if (spfResult.allQualifier == "fail") return { text: 'fail', cls: 'sec-partial' };
  if (spfResult.allQualifier == "pass") return { text: 'pass', cls: 'sec-partial' };
  if (spfResult.allQualifier == "neutral") return { text: 'neutral', cls: 'sec-partial' };
  
  return { text: 'Missing', cls: 'sec-missing' };
}
*/

function secLegendItem(label, colorKey, count) {
  return '<div class="legend-group" data-filter="' + colorKey + '">' +
    '<i class="legend-swatch" data-sec="' + colorKey + '" style="background:' + SEC_COLORS[colorKey] + '"></i>' +
    '<span>' + label + '(' + count +')' + '</span>' +
    '</div>';
}

function loadSecurityMap(mapConfig, countries) {

  // Erstelle Leafleat-Map und Grundlagenkarte (Open)
  var map = initMap('map', mapConfig);
  setupInfoBar(map);
  var isMobile = window.innerWidth <= 600;

  window.toggleSection = function(el) {
    el.classList.toggle('popup-toggle-open');
    var body = el.nextElementSibling;
    body.style.display = body.style.display === 'none' ? '' : 'none';
  };

  var allMuniLayers = [];
  var allLakeLayers = [];
  // Alle Kommunen (Länderübergreifend) munip-Objekte
  var allMuniData = [];


  // Farbenwechsel für jedes Geo-JSON Layer jedes Landes
  function toggleColorScheme() {
    var isDefault = SEC_COLORS === SEC_COLOR_SCHEMES.default;
    SEC_COLORS = isDefault ? SEC_COLOR_SCHEMES.colorblind : SEC_COLOR_SCHEMES.default; // Festlegen des Farbenobjekts

    for (var i = 0; i < allMuniLayers.length; i++) {
      var cc = countries[i];
      var md = allMuniData[i];
      allMuniLayers[i].eachLayer(function (layer) {
        var code = cc.featureCodeFn(layer.feature);
        var m = md[code];
        layer.setStyle({ fillColor: getSecurityColor(m) });
      });
    }


    for (var i = 0; i < allLakeLayers.length; i++) {
      if (allLakeLayers[i]) allLakeLayers[i].setStyle({ fillColor: SEC_COLORS.lake });
    }

    document.querySelectorAll('.legend-swatch').forEach(function (el) {
      if (el.dataset.sec) el.style.background = SEC_COLORS[el.dataset.sec];
    });

    var btn = document.querySelector('.color-toggle');
    btn.textContent = isDefault ? '\u25D0 Default colors' : '\u25D0 Colorblind mode';
  }
  // Holt alle JSON-Dateien mit daten und topoJSONFormat. Array je Land aus zwei JSON-Dateien { topo: topo, data: data }
  return fetchMultiCountryData(countries).then(function(results) {









    //Aggregierte Statistiken je Land -> Muss geändert werden
    var catCounts = { 
      '6/6': 0, '5/6': 0, '4/6' : 0, '3/6' : 0, '2/6' : 0, '1/6' : 0,  '0/6' : 0,
      'no_data': 0 };


    var latestGenerated = null;
    var latestCommit = null;

    for (var ci = 0; ci < results.length; ci++) {
      // Ziehe nur die Municipalities aus den Datensätzen der Länder (results) heraus
      var data = results[ci].data;
      var muni = data.municipalities;
      allMuniData.push(muni);

      // Wahrscheinlch: Nehme neustes Messdatum und Commit, wenn noch nicht existent
      if (data.generated && (!latestGenerated || data.generated > latestGenerated)) {
        latestGenerated = data.generated;
        latestCommit = data.commit;
      }

      // Klassifizierung und Abspeicherung: Bestimme wie viele Kommunen Sicherheitsmaßnahmen umsetzen je Land
    
      var keys = Object.keys(muni);
      for (var i = 0; i < keys.length; i++) {
        var cat = securityCategory(muni[keys[i]]);
        if (cat) {
          catCounts[cat]++;
        } else {
          catCounts['no-data']++;
        }
      }
    }

    //Metadaten
    if (latestGenerated) {

      showGenerated({ generated: latestGenerated, commit: latestCommit });
    }

    var hatchSvg = 'data:image/svg+xml,' +
      encodeURIComponent('<svg xmlns="http://www.w3.org/2000/svg" width="8" height="8"><rect width="8" height="8" fill="#BFBFBF"/><path d="M-1,1 l2,-2 M0,8 l8,-8 M7,9 l2,-2" stroke="#000" stroke-width="1"/></svg>');

    // Legendeninhalt (unten Rechts)
    // Control-Elemente, statisches HTML das nicht an geografische Koordinaten gebunden sind. Festgelegter Ort
    var legend = L.control({ position: isMobile ? 'topright' : 'bottomright' }); 

    legend.onAdd = function () { // Was passiert bei der Erstellung vom Controllelement
      var div = L.DomUtil.create('div', 'legend'); // Erstellung von div-Element und Zuweisung der der Klasse "legend"
      if (isMobile) div.classList.add('legend-collapsed');
      // Button ist nur für Mobilansichten gedacht





      div.innerHTML =
        '<button class="legend-toggle" aria-label="Toggle legend" aria-expanded="' + (!isMobile) + '">' + (isMobile ? 'Legend \u25B8' : '') + '</button>' +
        '<div class="legend-content">' +
        '<strong>Erfüllte Kriterien</strong><span class="legend-hint">click to filter</span>' +
        
        secLegendItem('6/6 ', '6/6', catCounts['6/6']) +
        secLegendItem('5/6', '5/6', catCounts['5/6']) +
        secLegendItem('4/6', '4/6', catCounts['4/6']) +
        secLegendItem('3/6', '3/6', catCounts['3/6']) +
        secLegendItem('2/6', '2/6', catCounts['2/6']) +
        secLegendItem('1/6', '1/6', catCounts['1/6']) +
        secLegendItem('0/6', '0/6', catCounts['0/6']) +
        '<div class="legend-group" data-filter="no-data"><i style="background-image:url(\'' + hatchSvg + '\')"></i>No scan data (' + catCounts['no-data'] + ')</div>' +
        '<button class="color-toggle" aria-label="Switch to colorblind-safe colors">\u25D0 Colorblind mode</button>' +
        '</div>';
      // <div class="legend-group" data-filter="' + colorKey + '"> -> Identifkation für Events



        L.DomEvent.disableClickPropagation(div); // Kein Klicken der Tieferen Ebene sichergestellt (Kartenebene/Markierung)
      return div;
    };

    // Control IdR visuell auf der höchsten Ebene  (über TileLayer und Polygonen, Popups) Lefleat steuert per CSS-Klasse 
    legend.addTo(map); 
    document.querySelector('.legend-toggle').addEventListener('click', toggleLegend);
    document.querySelector('.color-toggle').addEventListener('click', toggleColorScheme);

    // Category filter toggles
    var hiddenCats = {};

    // Aktualisierung der Layer:
    // Ermittle mithilfe der Feature-ID die Security-Kategorie jeder Kommune und prüfe ob sie aus oder weidereingeblendet 
    // werden soll
    function applyFilters() {
      for (var i = 0; i < allMuniLayers.length; i++) {
        var cc = countries[i];
        var md = allMuniData[i]; /*i -> Land*/
        // Wird für jede Kommunenweise (Polygonweise, wie eigene Layer) ausgeführt ->  Leafleat Befehl
        allMuniLayers[i].eachLayer(function (layer) {
          var code = cc.featureCodeFn(layer.feature); 
          var m = md[code];
          var cat = securityCategory(m) || 'no-data'; 
          var visible = !hiddenCats[cat]; 
          layer.setStyle({ fillOpacity: visible ? 1 : 0, opacity: visible ? 1 : 0 });
        });
      }
    }
    // legend-group Klassen mit attr. data-filter
    document.querySelectorAll('.legend-group[data-filter]').forEach(function (el) {
      el.addEventListener('click', function () {
        // data- ist ein Benutzerdefiniertes Attribut HTML5 Regel 
        // -> dataset-Objekt für jedes HTML-Element zur auslesung der Attribute
        // Präfix data- fällt weg / Bindestriche danach werden von a-b zu aB
        var cat = el.dataset.filter; // Hier: Farbcode also z.B: dmarc-only
        hiddenCats[cat] = !hiddenCats[cat]; // Wertumkehr für Kategorie, wenn noch nicht existent dann wird für cat Element angelegt
        el.classList.toggle('legend-hidden', hiddenCats[cat]); // Entfernen (wenn vorhanden) bzw. Hinzufügen der CSS-Klasse
        applyFilters(); // Aktualisiere für jedes Land die Ansicht. 
      });
    });

    // Render each country
    for (var ci = 0; ci < results.length; ci++) {
      var topo = results[ci].topo;
      var cc = countries[ci];
      var muni = allMuniData[ci];

      //Layer: Topo -> GeoJSON Füge Seen als separate Layer hinzu, damit sie immer sichtbar sind
      allLakeLayers.push(addLakes(map, topo, SEC_COLORS.lake));

      // GeoJSON Konvertierung
      var geojson = topojson.feature(topo, topo.objects[cc.topoObject]); // cc.topoObject Name des Topo Objects z.b.municipalities in CH

      // IIFE: Funktion wird direkt ausgeführt -> Ergebnis GeoJSON LAyerobjekt
      var muniLayer = (function(cc, muni, geojson) {
        return L.geoJSON(geojson, {
          style: function (feature) { // Bestimme Farbe je Kommune
            var code = cc.featureCodeFn(feature); // Identifikation Kommune über featureCodeFunktion (id des Features)
            
            var m = muni[code];   // Featureweises Styling in Abhängigkeit von id des Features nach https://leafletjs.com/examples/geojson/
            return { 
              fillColor: getSecurityColor(m), 
              weight: 0.6,
              color: '#666',
              fillOpacity: 1
            };
          },
          onEachFeature: function (feature, layer) { // Popup-Inhalt bestimmen
            var code = cc.featureCodeFn(feature); 
            var m = muni[code];
            if (!m) {
              layer.bindPopup('<div class="info-popup"><strong>ID ' + escapeHtml(code) + '</strong><br>No data</div>');
              return;
            }

            var regionCode = cc.REGION_CODES[m.region] || ''; // Bundesland
            var nameDisplay = regionCode ? escapeHtml(m.name) + ' (' + regionCode + ')' : escapeHtml(m.name);
            var eDomain = escapeHtml(m.domainname || 'unknown');
            var showBody = isMobile ? 'display:none' : '';

            //var spf = spfLabel(m); // return { text, cls }
            //var dmarc = dmarcLabel(m.dss);

            var statusHtml =
              '<div class="sec-status">' +
              /*
              '<div class="sec-row"><span class="sec-label">SPF</span><span class="sec-badge ' + spf.cls + '">' + spf.text + '</span></div>' +
              //'<div class="sec-row"><span class="sec-label">DMARC</span><span class="sec-badge ' + dmarc.cls + '">' + dmarc.text + '</span></div>' +
              '</div>';

            // MX Tabelle
            
            var mxHosts = m.mx_records || [];
            var mxSection;
            if (mxHosts.length > 0) {
              var mxRows = mxHosts.map(function(h) {
                return '<tr><td class="host">' + escapeHtml(h) + '</td></tr>';
              }).join(''); 
              mxSection = '<div class="popup-section"><div class="popup-toggle" onclick="window.toggleSection(this)">MX records</div><div class="popup-section-body" style="display:none"><table class="dns-table">' + mxRows + '</table></div></div>';
            } else {
              mxSection = '<div class="popup-section"><div class="popup-toggle" onclick="window.toggleSection(this)">MX records</div><div class="popup-section-body" style="display:none"><span class="popup-empty">No MX records</span></div></div>';
            }
              */
            // Popup-Inhalt
            layer.bindPopup(
              '<div class="info-popup">' +
              '<strong>' + nameDisplay + '</strong><br>' +
              '<strong>' +'Domain:' + '</strong>' + eDomain + '<br>'+ 
              '<strong>' + 'Record:'  + '</strong>' + getRecord(m) + '<br>' +
               getErrorMessage(m) + '<br>' +
              '</div>',
              { maxWidth: isMobile ? 300 : 400 }
            );
            layer.on('mouseover', function () { this.setStyle({ weight: 2, color: '#333' }); });
            layer.on('mouseout', function () { this.setStyle({ weight: 0.6, color: '#666' }); });
          }
        }).addTo(map); // Direkte Ausführung für das jeweilige Land // AddTo ändert das Leafleat-Layer nicht
      })(cc, muni, geojson); 

      allMuniLayers.push(muniLayer); // Wichtige Zwischenspeicherung des Lefleat-Objekts damit für das jeweilige Land der Filter funktioniert
    }

    // Country outlines on top -> Für TopoJSON
    for (var ci = 0; ci < results.length; ci++) {
      addCountryOutline(map, results[ci].topo, countries[ci].topoObject); 
    }

    removeLoading();
    map.invalidateSize({ animate: false });
    addDownloadButton(map, 'security-map.png');
  });
}
