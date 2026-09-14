import { useEffect, useRef, useState } from 'react'
import L from 'leaflet'
import { Layers, Maximize2, Minimize2, Navigation, ShieldAlert, Crosshair } from 'lucide-react'
import { GeoHop, GeoLookupResponse } from '../api/client'

export interface MapMarkerItem {
  id: string
  ip: string
  lat: number
  lon: number
  city?: string
  country?: string
  country_code?: string
  isp?: string
  org?: string
  asn?: string
  role?: string
  threat_score?: number
  threat_tier?: {
    tier: string
    score: number
    color: string
    bg_color: string
    border_color: string
    label: string
    typical: string
  }
  cardinal_coords?: string
  confidence_statement?: string
  isDeviceLocation?: boolean
}

interface Props {
  markers: MapMarkerItem[]
  hops?: GeoHop[]
  flyTo?: { lat: number; lon: number; zoom?: number; id?: string } | null
  height?: string
  showTileSwitcher?: boolean
  showRadius?: boolean
  selectedMarkerId?: string | null
  defaultBasemap?: BasemapType
  onMarkerClick?: (marker: MapMarkerItem) => void
}

type BasemapType = 'osm' | 'dark_matter' | 'esri_dark'

const BASEMAP_URLS: Record<BasemapType, { name: string; url: string; subdomains?: string; attribution: string }> = {
  osm: {
    name: 'OSM Standard',
    url: 'https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png',
    attribution: '&copy; OpenStreetMap contributors',
  },
  dark_matter: {
    name: 'CartoDB Dark',
    url: 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',
    subdomains: 'abcd',
    attribution: '&copy; OpenStreetMap &copy; CARTO',
  },
  esri_dark: {
    name: 'ESRI Cyber Dark',
    url: 'https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}',
    attribution: '&copy; Esri &mdash; Esri, DeLorme, NAVTEQ',
  },
}

export default function GeoLocationMap({
  markers,
  hops = [],
  flyTo = null,
  height = '440px',
  showTileSwitcher = true,
  showRadius = true,
  selectedMarkerId = null,
  defaultBasemap = 'osm',
  onMarkerClick,
}: Props) {
  const mapContainerRef = useRef<HTMLDivElement>(null)
  const mapInstanceRef = useRef<L.Map | null>(null)
  const tileLayerRef = useRef<L.TileLayer | null>(null)
  const markersLayerRef = useRef<L.LayerGroup | null>(null)
  const linesLayerRef = useRef<L.LayerGroup | null>(null)
  const markerObjectsRef = useRef<Record<string, L.Marker>>({})
  const activePopupIdRef = useRef<string | null>(null)

  const [activeBasemap, setActiveBasemap] = useState<BasemapType>(defaultBasemap)
  const [isFullscreen, setIsFullscreen] = useState(false)

  // Initialize Leaflet map instance
  useEffect(() => {
    if (!mapContainerRef.current || mapInstanceRef.current) return

    const initialCenter: [number, number] = markers.length > 0
      ? [markers[0].lat, markers[0].lon]
      : [25.0, 10.0]
    const initialZoom = markers.length > 0 ? 4 : 2

    const map = L.map(mapContainerRef.current, {
      center: initialCenter,
      zoom: initialZoom,
      zoomControl: false,
      worldCopyJump: true,
      attributionControl: false,
    })

    // Custom bottom-right zoom control
    L.control.zoom({ position: 'bottomright' }).addTo(map)

    // Layer groups for markers and routing lines
    const markersGroup = L.layerGroup().addTo(map)
    const linesGroup = L.layerGroup().addTo(map)

    mapInstanceRef.current = map
    markersLayerRef.current = markersGroup
    linesLayerRef.current = linesGroup

    // Set initial tile layer
    const cfg = BASEMAP_URLS[activeBasemap]
    const tiles = L.tileLayer(cfg.url, {
      subdomains: cfg.subdomains || 'abc',
      maxZoom: 19,
    }).addTo(map)
    tileLayerRef.current = tiles

    // Invalidate size on resize
    const resizeObserver = new ResizeObserver(() => {
      map.invalidateSize()
    })
    resizeObserver.observe(mapContainerRef.current)

    return () => {
      resizeObserver.disconnect()
      map.remove()
      mapInstanceRef.current = null
    }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  // Switch basemap tiles
  useEffect(() => {
    if (!mapInstanceRef.current) return
    const map = mapInstanceRef.current
    if (tileLayerRef.current) {
      map.removeLayer(tileLayerRef.current)
    }
    const cfg = BASEMAP_URLS[activeBasemap]
    const tiles = L.tileLayer(cfg.url, {
      subdomains: cfg.subdomains || 'abc',
      maxZoom: 19,
    }).addTo(map)
    tileLayerRef.current = tiles
  }, [activeBasemap])

  // Update markers, pulse waves, ±35km circles, and popups
  useEffect(() => {
    if (!mapInstanceRef.current || !markersLayerRef.current) return

    const markersGroup = markersLayerRef.current
    markersGroup.clearLayers()
    markerObjectsRef.current = {}

    markers.forEach(item => {
      if (item.lat === undefined || item.lon === undefined) return
      if (item.lat === 0 && item.lon === 0) return

      const color = item.isDeviceLocation
        ? '#06b6d4'
        : item.threat_tier?.color || '#f87171'

      const isDevice = Boolean(item.isDeviceLocation)
      const pinLabel = isDevice ? 'YOU' : item.threat_tier?.tier?.toUpperCase() || 'NODE'

      // Custom Downward Tactical Pin with Concentric Radar Pulse Wave
      const iconHtml = `
        <div class="relative flex flex-col items-center justify-center cursor-pointer group" style="transform: translate(-50%, -100%);">
          <!-- Concentric Radar Pulse Waves -->
          <div class="absolute -top-1 left-1/2 -translate-x-1/2 -translate-y-1/2 w-10 h-10 rounded-full tactical-pulse-wave pointer-events-none"
               style="background-color: ${color};"></div>
          <div class="absolute -top-1 left-1/2 -translate-x-1/2 -translate-y-1/2 w-6 h-6 rounded-full tactical-pulse-wave pointer-events-none"
               style="background-color: ${color}; animation-delay: 0.7s;"></div>

          <!-- Tactical SVG Pointer Pin -->
          <svg width="34" height="42" viewBox="0 0 34 42" fill="none" xmlns="http://www.w3.org/2000/svg" class="drop-shadow-lg transition-transform duration-200 group-hover:scale-110">
            <!-- Pin Body -->
            <path d="M17 0C7.611 0 0 7.611 0 17C0 27.5 14.5 40.5 16.2 41.8C16.6 42.1 17.4 42.1 17.8 41.8C19.5 40.5 34 27.5 34 17C34 7.611 26.389 0 17 0Z"
                  fill="#0f172a" stroke="${color}" stroke-width="2.5"/>
            <!-- Center Glowing Dot -->
            <circle cx="17" cy="17" r="7" fill="${color}" stroke="#ffffff" stroke-width="2"/>
          </svg>

          <!-- Tactical Badge Pill -->
          <div class="mt-0.5 px-1.5 py-0.2 text-[9px] font-mono font-extrabold rounded-md shadow-md uppercase tracking-wider text-white"
               style="background-color: ${color};">
            ${pinLabel}
          </div>
        </div>
      `

      const customIcon = L.divIcon({
        className: 'tactical-map-pin',
        html: iconHtml,
        iconSize: [34, 42],
        iconAnchor: [17, 42],
        popupAnchor: [0, -42],
      })

      const marker = L.marker([item.lat, item.lon], { icon: customIcon })

      // ±35km Uncertainty Radius Circle
      if (showRadius && !isDevice) {
        const radiusCircle = L.circle([item.lat, item.lon], {
          radius: 35000, // 35 km
          color: color,
          weight: 1.5,
          dashArray: '5, 8',
          fillColor: color,
          fillOpacity: 0.08,
          interactive: false,
        })
        markersGroup.addLayer(radiusCircle)
      }

      // Determine real physical place name
      const actualLocation = (
        (item.city && item.country && !item.city.toLowerCase().includes('device coordinate') && !item.city.toLowerCase().includes('current device'))
          ? `${item.city}, ${item.country}`
          : item.org && !item.org.toLowerCase().includes('device coordinate') && !item.org.toLowerCase().includes('physical device location')
            ? item.org
            : item.country && !item.country.toLowerCase().includes('gps resolved')
              ? item.country
              : 'Physical Location Identified'
      )

      const confidenceStmt = item.confidence_statement || (
        item.city && item.country
          ? `The approximate location is ${item.city}, ${item.country} with 90% confidence`
          : 'Approximate carrier network location'
      )
      const cardinalStr = item.cardinal_coords || `${item.lat.toFixed(4)}°, ${item.lon.toFixed(4)}°`

      const popupContent = `
        <div class="font-sans text-slate-900 min-w-[270px] max-w-[320px] p-1">
          <!-- Header with Threat Tier Badge -->
          <div class="flex items-center justify-between gap-2 border-b border-slate-200 pb-2 mb-2">
            <div class="font-mono text-xs font-bold flex items-center gap-1.5 text-slate-900">
              <span class="w-2.5 h-2.5 rounded-full" style="background-color: ${color};"></span>
              <span class="truncate max-w-[170px]">${item.ip}</span>
            </div>
            <span class="text-[10px] font-bold font-mono px-2 py-0.5 rounded-full text-white shadow-sm flex-shrink-0"
                  style="background-color: ${color};">
              ${isDevice ? 'DEVICE GPS' : `${item.threat_tier?.label || 'THREAT'} (${item.threat_score ?? 0}%)`}
            </span>
          </div>

          <!-- Prominent Actual Physical Location -->
          <div class="mb-2 p-2.5 bg-blue-50/90 border border-blue-200 rounded-xl">
            <div class="text-[9px] font-bold text-blue-700 uppercase tracking-wider flex items-center gap-1 mb-0.5">
              <span>📍 Actual Physical Location</span>
            </div>
            <div class="text-xs font-bold text-slate-900 leading-snug">
              ${actualLocation}
            </div>
            <div class="text-[10px] text-slate-500 font-mono mt-0.5 flex items-center justify-between">
              <span>${cardinalStr}</span>
              <span class="text-[9px] text-blue-600 font-sans font-semibold">${isDevice ? 'GPS Exact' : 'ISP Gateway'}</span>
            </div>
          </div>

          <!-- Formal Geolocation Statement -->
          ${
            confidenceStmt && !confidenceStmt.toLowerCase().includes('device coordinates') && !confidenceStmt.includes(actualLocation)
              ? `<div class="text-[11px] font-medium text-slate-700 mb-2 leading-tight bg-slate-50 p-2 rounded-lg border border-slate-200">
                  ${confidenceStmt}
                </div>`
              : ''
          }

          <!-- Forensic Key-Value Grid -->
          <div class="grid grid-cols-2 gap-1.5 text-[11px] mb-2 font-mono">
            <div class="bg-slate-50 p-1.5 rounded border border-slate-200">
              <div class="text-[9px] text-slate-500 font-sans">Coordinates</div>
              <div class="font-semibold text-slate-800 truncate">${cardinalStr}</div>
            </div>
            <div class="bg-slate-50 p-1.5 rounded border border-slate-200">
              <div class="text-[9px] text-slate-500 font-sans">ASN / Autonomous System</div>
              <div class="font-semibold text-slate-800 truncate">${item.asn || 'AS Unknown'}</div>
            </div>
            <div class="col-span-2 bg-slate-50 p-1.5 rounded border border-slate-200">
              <div class="text-[9px] text-slate-500 font-sans">Carrier / Organization</div>
              <div class="font-semibold text-slate-800 truncate">${item.isp || item.org || 'Unknown Carrier'}</div>
            </div>
          </div>

          <!-- Role / Threat Context -->
          ${
            item.role
              ? `<div class="text-[10px] text-slate-600 flex items-center justify-between pt-1 border-t border-slate-100">
                  <span class="text-slate-500 font-sans">Role:</span>
                  <span class="font-bold text-slate-800 font-mono">${item.role}</span>
                </div>`
              : ''
          }
          ${
            showRadius && !isDevice
              ? `<div class="mt-1 text-[9px] text-slate-400 text-center font-sans italic">
                  Dashed perimeter indicates ±35 km carrier uncertainty radius
                </div>`
              : ''
          }
        </div>
      `

      marker.bindPopup(popupContent, {
        className: 'tactical-forensic-popup',
        maxWidth: 340,
      })

      marker.on('click', () => {
        activePopupIdRef.current = item.id
        if (onMarkerClick) onMarkerClick(item)
      })

      marker.on('popupopen', () => {
        activePopupIdRef.current = item.id
      })

      markersGroup.addLayer(marker)
      markerObjectsRef.current[item.id] = marker
    })

    // If a marker was open, selected, or is the flyTo target, re-open its popup on the new layer
    const targetPopupId = flyTo?.id || selectedMarkerId || activePopupIdRef.current
    if (targetPopupId && markerObjectsRef.current[targetPopupId]) {
      markerObjectsRef.current[targetPopupId].openPopup()
    }
  }, [markers, showRadius, onMarkerClick, selectedMarkerId, flyTo])

  // Multi-hop routing lines
  useEffect(() => {
    if (!mapInstanceRef.current || !linesLayerRef.current) return
    const linesGroup = linesLayerRef.current
    linesGroup.clearLayers()

    // Extract valid coordinates from hops
    const hopCoords: [number, number][] = []
    hops.forEach(h => {
      if (h.lat !== undefined && h.lon !== undefined && h.lat !== null && h.lon !== null) {
        if (h.lat !== 0 || h.lon !== 0) {
          hopCoords.push([h.lat, h.lon])
        }
      }
    })

    if (hopCoords.length > 1) {
      // Draw animated dashed polyline
      const polyline = L.polyline(hopCoords, {
        color: '#3b82f6',
        weight: 2.5,
        opacity: 0.85,
        dashArray: '6, 8',
      })
      linesGroup.addLayer(polyline)

      // Add waypoint circles for intermediate hops
      hopCoords.forEach((coord, idx) => {
        const waypointMarker = L.circleMarker(coord, {
          radius: 5,
          color: '#ffffff',
          weight: 2,
          fillColor: idx === 0 ? '#ef4444' : '#3b82f6',
          fillOpacity: 1,
        })
        linesGroup.addLayer(waypointMarker)
      })
    }
  }, [hops])

  // Handle Fly-To camera navigation with guaranteed popup opening
  useEffect(() => {
    if (!flyTo || !mapInstanceRef.current) return
    const map = mapInstanceRef.current
    const targetZoom = flyTo.zoom || 7

    map.flyTo([flyTo.lat, flyTo.lon], targetZoom, {
      duration: 1.5,
      easeLinearity: 0.25,
    })

    if (flyTo.id) {
      const targetId = flyTo.id
      activePopupIdRef.current = targetId

      // Retry opening popup until marker is mounted in Leaflet
      let attempts = 0
      const checkAndOpen = () => {
        attempts++
        const m = markerObjectsRef.current[targetId]
        if (m) {
          m.openPopup()
        } else if (attempts < 30) {
          setTimeout(checkAndOpen, 100)
        }
      }
      setTimeout(checkAndOpen, 400)
    }
  }, [flyTo])

  // Fit bounds if markers change and no specific flyTo is set
  useEffect(() => {
    if (!mapInstanceRef.current || markers.length === 0 || flyTo) return
    const validMarkers = markers.filter(m => m.lat && m.lon && (m.lat !== 0 || m.lon !== 0))
    if (validMarkers.length === 0) return

    if (validMarkers.length === 1) {
      mapInstanceRef.current.setView([validMarkers[0].lat, validMarkers[0].lon], 5)
    } else {
      const bounds = L.latLngBounds(validMarkers.map(m => [m.lat, m.lon]))
      mapInstanceRef.current.fitBounds(bounds, { padding: [40, 40], maxZoom: 8 })
    }
  }, [markers.length]) // eslint-disable-line react-hooks/exhaustive-deps

  const toggleFullscreen = () => {
    setIsFullscreen(prev => !prev)
    setTimeout(() => {
      mapInstanceRef.current?.invalidateSize()
    }, 150)
  }

  const handleResetView = () => {
    if (!mapInstanceRef.current || markers.length === 0) return
    const valid = markers.filter(m => m.lat && m.lon && (m.lat !== 0 || m.lon !== 0))
    if (valid.length === 0) return
    const bounds = L.latLngBounds(valid.map(m => [m.lat, m.lon]))
    mapInstanceRef.current.fitBounds(bounds, { padding: [40, 40], maxZoom: 8 })
  }

  return (
    <div
      className={`relative overflow-hidden rounded-2xl border border-slate-200 shadow-sm bg-slate-950 transition-all ${
        isFullscreen ? 'fixed inset-0 z-50 rounded-none h-screen w-screen' : ''
      }`}
      style={{ height: isFullscreen ? '100vh' : height }}
    >
      {/* Map DOM Container */}
      <div ref={mapContainerRef} className="w-full h-full z-0" />

      {/* Top Floating Controls */}
      <div className="absolute top-3 left-3 right-3 z-10 flex items-center justify-between gap-2 pointer-events-none">
        {/* Left: Tactical Radar Header Badge */}
        <div className="pointer-events-auto flex items-center gap-2 bg-slate-900/90 text-white border border-slate-800 backdrop-blur-md px-3 py-1.5 rounded-xl shadow-lg text-xs font-semibold">
          <span className="relative flex h-2.5 w-2.5">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-blue-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-blue-500"></span>
          </span>
          <span>ThreatLens Global Radar</span>
          <span className="text-[10px] text-slate-400 font-mono">({markers.length} {markers.length === 1 ? 'target' : 'targets'})</span>
        </div>

        {/* Right Controls: Basemap Switcher & Actions */}
        <div className="pointer-events-auto flex items-center gap-2">
          {showTileSwitcher && (
            <div className="flex items-center bg-slate-900/90 border border-slate-800 backdrop-blur-md p-1 rounded-xl shadow-lg text-[11px] font-medium text-slate-300">
              {(['osm', 'dark_matter', 'esri_dark'] as BasemapType[]).map(type => (
                <button
                  key={type}
                  onClick={() => setActiveBasemap(type)}
                  className={`px-2.5 py-1 rounded-lg transition-all ${
                    activeBasemap === type
                      ? 'bg-blue-600 text-white font-semibold shadow-sm'
                      : 'hover:text-white hover:bg-slate-800/80'
                  }`}
                >
                  {BASEMAP_URLS[type].name}
                </button>
              ))}
            </div>
          )}

          <button
            onClick={handleResetView}
            className="p-2 rounded-xl bg-slate-900/90 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-800 backdrop-blur-md shadow-lg transition-colors"
            title="Reset Map View"
          >
            <Crosshair className="h-4 w-4" />
          </button>

          <button
            onClick={toggleFullscreen}
            className="p-2 rounded-xl bg-slate-900/90 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-800 backdrop-blur-md shadow-lg transition-colors"
            title={isFullscreen ? 'Exit Fullscreen' : 'Expand Fullscreen'}
          >
            {isFullscreen ? <Minimize2 className="h-4 w-4" /> : <Maximize2 className="h-4 w-4" />}
          </button>
        </div>
      </div>

      {/* Legend Bar at Bottom Left */}
      <div className="absolute bottom-3 left-3 z-10 pointer-events-auto bg-slate-900/90 text-white border border-slate-800 backdrop-blur-md px-3 py-2 rounded-xl shadow-lg text-[10px] flex items-center gap-3 flex-wrap">
        <span className="text-slate-400 font-semibold uppercase tracking-wider">Threat Tiers:</span>
        <span className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-[#990000] ring-2 ring-red-900/50"></span>
          <span>Critical (&ge;80%)</span>
        </span>
        <span className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-[#f87171]"></span>
          <span>High (60-79%)</span>
        </span>
        <span className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-[#facc15]"></span>
          <span>Medium (40-59%)</span>
        </span>
        <span className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-[#166534]"></span>
          <span>Low (15-39%)</span>
        </span>
        <span className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-[#4ade80]"></span>
          <span>Safe (0-14%)</span>
        </span>
        <span className="flex items-center gap-1.5 pl-2 border-l border-slate-800">
          <span className="w-2.5 h-2.5 rounded-full bg-[#06b6d4]"></span>
          <span>You (Device)</span>
        </span>
      </div>
    </div>
  )
}
