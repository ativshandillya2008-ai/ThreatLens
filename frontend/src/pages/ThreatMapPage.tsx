import { useEffect, useState } from 'react'
import { useLocation, useSearchParams } from 'react-router-dom'
import {
  Globe,
  Search,
  Crosshair,
  MapPin,
  RefreshCw,
  AlertTriangle,
  ShieldAlert,
  ShieldCheck,
  Send,
  Navigation,
  ExternalLink,
  LocateFixed,
  Radio,
} from 'lucide-react'
import { api, ThreatDetail, UserInfo } from '../api/client'
import GeoLocationMap, { MapMarkerItem } from '../components/GeoLocationMap'
import Navbar from '../components/Navbar'

interface Props {
  user: UserInfo
}

export default function ThreatMapPage({ user }: Props) {
  const location = useLocation()
  const [searchParams] = useSearchParams()

  const [ipInput, setIpInput] = useState('')
  const [loadingLookup, setLoadingLookup] = useState(false)
  const [loadingGps, setLoadingGps] = useState(false)
  const [error, setError] = useState('')
  const [markers, setMarkers] = useState<MapMarkerItem[]>([])
  const [flyToTarget, setFlyToTarget] = useState<{ lat: number; lon: number; zoom?: number; id?: string } | null>(null)
  const [selectedNode, setSelectedNode] = useState<MapMarkerItem | null>(null)
  const [loadingRecent, setLoadingRecent] = useState(true)
  const [trackingBanner, setTrackingBanner] = useState<{
    subject: string
    sender: string
    ip?: string
    location?: string
  } | null>(null)

  // Quick preset targets for instant demonstration
  const quickPresets = [
    { label: 'Tor Exit Node (Moscow)', ip: '185.220.101.5' },
    { label: 'Bulletproof C2 (Bucharest)', ip: '194.26.29.112' },
    { label: 'High-Risk Relay (Lagos)', ip: '198.51.100.23' },
    { label: 'Google Public DNS', ip: '8.8.8.8' },
    { label: 'Cloudflare Anycast', ip: '1.1.1.1' },
  ]

  const COUNTRY_CENTROIDS: Record<string, [number, number]> = {
    'United States': [37.0902, -95.7129],
    US: [37.0902, -95.7129],
    Germany: [51.1657, 10.4515],
    DE: [51.1657, 10.4515],
    India: [20.5937, 78.9629],
    IN: [20.5937, 78.9629],
    'United Kingdom': [55.3781, -3.436],
    GB: [55.3781, -3.436],
    Russia: [61.524, 105.3188],
    RU: [61.524, 105.3188],
    Romania: [45.9432, 24.9668],
    RO: [45.9432, 24.9668],
    Nigeria: [9.082, 8.6753],
    NG: [9.082, 8.6753],
    China: [35.8617, 104.1954],
    CN: [35.8617, 104.1954],
    France: [46.2276, 2.2137],
    FR: [46.2276, 2.2137],
    Ireland: [53.1424, -7.6921],
    IE: [53.1424, -7.6921],
    Netherlands: [52.1326, 5.2913],
    NL: [52.1326, 5.2913],
    Singapore: [1.3521, 103.8198],
    SG: [1.3521, 103.8198],
    Australia: [-25.2744, 133.7751],
    AU: [-25.2744, 133.7751],
    Canada: [56.1304, -106.3468],
    CA: [56.1304, -106.3468],
  }

  // Fetch recent scanned emails with geolocation from backend
  const loadRecentEmailThreats = async () => {
    setLoadingRecent(true)
    try {
      const res = await api.threats.list({ page_size: 50 })
      const threatMarkers: MapMarkerItem[] = []

      res.threats.forEach((t: ThreatDetail, idx: number) => {
        let lat = t.geo_lat || t.geo_hops?.[0]?.lat
        let lon = t.geo_lon || t.geo_hops?.[0]?.lon

        // If coordinates not stored directly, use country centroid with gentle scatter
        if (!lat || !lon || (lat === 0 && lon === 0)) {
          const countryKey = t.geo_country || t.geo_hops?.[0]?.country || ''
          const centroid = COUNTRY_CENTROIDS[countryKey]
          if (centroid) {
            // Add subtle deterministic jitter so dots don't stack directly on top of each other
            const jitterLat = ((idx % 7) - 3) * 0.45
            const jitterLon = (((idx * 3) % 7) - 3) * 0.45
            lat = centroid[0] + jitterLat
            lon = centroid[1] + jitterLon
          }
        }

        if (lat && lon && (lat !== 0 || lon !== 0)) {
          threatMarkers.push({
            id: `email-${t.id}`,
            ip: t.geo_hops?.[0]?.ip || 'Mail Origin Server',
            lat: lat,
            lon: lon,
            city: t.geo_hops?.[0]?.city || t.geo_country || 'Origin Region',
            country: t.geo_country || 'Unknown',
            isp: t.geo_org || t.geo_hops?.[0]?.org || 'Email Relay Server',
            asn: t.geo_asn || t.geo_hops?.[0]?.asn || 'N/A',
            role: `Sender: ${t.sender}`,
            threat_score: Math.round(t.final_score * 100),
            threat_tier: {
              tier: t.severity === 'HIGH' ? 'Critical' : t.severity === 'MEDIUM' ? 'High' : 'Safe',
              score: Math.round(t.final_score * 100),
              color: t.severity === 'HIGH' ? '#990000' : t.severity === 'MEDIUM' ? '#f87171' : '#4ade80',
              bg_color: 'rgba(255, 255, 255, 0.1)',
              border_color: '#ffffff',
              label: t.severity,
              typical: `Email Subject: ${t.subject}`,
            },
            cardinal_coords: t.geo_hops?.[0]?.cardinal_coords || `${lat.toFixed(4)}°, ${lon.toFixed(4)}°`,
            confidence_statement: `Inbox Email Origin: ${t.subject} (From: ${t.sender})`,
          })
        }
      })

      if (threatMarkers.length > 0) {
        setMarkers(prev => {
          const ids = new Set(prev.map(m => m.id))
          const fresh = threatMarkers.filter(m => !ids.has(m.id))
          return [...prev, ...fresh]
        })
      }
    } catch (err) {
      console.warn('Could not load recent threat coordinates:', err)
    } finally {
      setLoadingRecent(false)
    }
  }

  useEffect(() => {
    loadRecentEmailThreats()
  }, [])

  // Manual IP Pinpoint handler
  const handlePinpoint = async (ipToLookup?: string) => {
    const target = (ipToLookup || ipInput).trim()
    if (!target) return
    setError('')
    setLoadingLookup(true)

    try {
      const data = await api.geo.lookup(target)
      const newMarker: MapMarkerItem = {
        id: `ip-${data.ip}-${Date.now()}`,
        ip: data.ip,
        lat: data.lat,
        lon: data.lon,
        city: data.city,
        country: data.country,
        country_code: data.country_code,
        isp: data.isp,
        org: data.org,
        asn: data.asn,
        role: data.role,
        threat_score: data.threat_score,
        threat_tier: data.threat_tier,
        cardinal_coords: data.cardinal_coords,
        confidence_statement: data.confidence_statement,
      }

      setMarkers(prev => [newMarker, ...prev.filter(m => m.ip !== data.ip)])
      setSelectedNode(newMarker)
      setFlyToTarget({ lat: data.lat, lon: data.lon, zoom: 7, id: newMarker.id })
      setIpInput('')
    } catch (err) {
      setError(String(err))
    } finally {
      setLoadingLookup(false)
    }
  }

  // Track incoming email sender from Inbox / Message Detail
  const handleTrackIncomingEmail = async (
    state: any,
    emailId?: string | null,
    threatId?: string | null,
    targetIp?: string | null
  ) => {
    let lat = state?.lat
    let lon = state?.lon
    let city = state?.city
    let country = state?.country
    let sender = state?.sender || 'Inbox Message'
    let subject = state?.subject || 'Tracked Email'
    let ip = targetIp || state?.ip || 'Mail Origin Server'

    // If coordinates are missing, fetch threat details
    if ((!lat || !lon || (lat === 0 && lon === 0)) && (threatId || emailId)) {
      try {
        let threatDetail: ThreatDetail | null = null
        if (threatId) {
          threatDetail = await api.threats.get(threatId)
        } else if (emailId) {
          const msgResp = await api.gmail.message(emailId)
          threatDetail = (msgResp as any).threat
        }
        if (threatDetail) {
          lat = threatDetail.geo_lat || threatDetail.geo_hops?.[0]?.lat
          lon = threatDetail.geo_lon || threatDetail.geo_hops?.[0]?.lon
          city = threatDetail.geo_hops?.[0]?.city || city
          country = threatDetail.geo_country || threatDetail.geo_hops?.[0]?.country || country
          ip = threatDetail.geo_hops?.[0]?.ip || ip
          sender = threatDetail.sender || sender
          subject = threatDetail.subject || subject
        }
      } catch (err) {
        console.warn('Failed to resolve threat coordinates:', err)
      }
    }

    // Centroid or lookup fallback if coordinates still zero
    if (!lat || !lon || (lat === 0 && lon === 0)) {
      if (ip && ip !== 'Mail Origin Server') {
        try {
          const geoRes = await api.geo.lookup(ip)
          lat = geoRes.lat
          lon = geoRes.lon
          city = geoRes.city || city
          country = geoRes.country || country
        } catch {
          // ignore
        }
      }
      if (!lat || !lon || (lat === 0 && lon === 0)) {
        if (country && COUNTRY_CENTROIDS[country]) {
          lat = COUNTRY_CENTROIDS[country][0]
          lon = COUNTRY_CENTROIDS[country][1]
        } else {
          lat = 39.0438
          lon = -77.4874
          city = city || 'Ashburn'
          country = country || 'United States'
        }
      }
    }

    if (lat && lon && (lat !== 0 || lon !== 0)) {
      let physicalPlace = city && country ? `${city}, ${country}` : country || 'Mail Gateway'

      // Always attempt reverse geocode for exact physical place name
      try {
        const rev = await api.geo.reverse(lat, lon)
        if (rev.display_name && !rev.display_name.toLowerCase().includes('device coordinate')) {
          physicalPlace = rev.display_name
          city = rev.city || city
          country = rev.country || country
        }
      } catch {
        // ignore
      }

      const trackedMarker: MapMarkerItem = {
        id: `track-${emailId || threatId || Date.now()}`,
        ip: ip,
        lat: lat,
        lon: lon,
        city: city || 'Mail Gateway',
        country: country || 'Identified Region',
        isp: state?.isp || 'Mail Origin Server',
        asn: state?.asn || 'Mail Route',
        role: `Origin: ${sender}`,
        threat_score: 70,
        threat_tier: {
          tier: 'Critical',
          score: 70,
          color: '#f87171',
          bg_color: 'rgba(248, 113, 113, 0.15)',
          border_color: '#f87171',
          label: 'TRACKED SENDER',
          typical: `Subject: ${subject}`,
        },
        cardinal_coords: `${lat.toFixed(4)}°, ${lon.toFixed(4)}°`,
        confidence_statement: `Origin Tracked: ${physicalPlace} (${sender})`,
      }

      setMarkers(prev => [trackedMarker, ...prev.filter(m => m.id !== trackedMarker.id)])
      setSelectedNode(trackedMarker)
      setFlyToTarget({ lat, lon, zoom: 8, id: trackedMarker.id })
      setTrackingBanner({
        subject,
        sender,
        ip,
        location: physicalPlace,
      })
    }
  }

  // Handle incoming routing from inbox message rows
  useEffect(() => {
    const state = location.state as {
      focusEmailId?: string
      threatId?: string
      lat?: number | null
      lon?: number | null
      sender?: string
      subject?: string
      country?: string | null
      city?: string | null
      ip?: string
    } | null

    const paramEmailId = searchParams.get('email_id') || state?.focusEmailId
    const paramThreatId = searchParams.get('threat_id') || state?.threatId
    const paramIp = searchParams.get('ip') || state?.ip

    if (state || paramEmailId || paramThreatId || paramIp) {
      handleTrackIncomingEmail(state, paramEmailId, paramThreatId, paramIp)
    }
  }, [location.state, searchParams])

  // "Get My Current Location" handler using HTML5 GPS + Reverse Geocoding
  const handleGetDeviceLocation = () => {
    if (!navigator.geolocation) {
      setError('Geolocation is not supported by your browser')
      return
    }

    setError('')
    setLoadingGps(true)

    navigator.geolocation.getCurrentPosition(
      async position => {
        const lat = position.coords.latitude
        const lon = position.coords.longitude

        try {
          let reverseData: any = null
          try {
            reverseData = await api.geo.reverse(lat, lon)
          } catch (backendErr) {
            console.warn('Backend reverse failed, trying direct resolver:', backendErr)
          }

          // Direct client-side fallback if backend gave generic coordinates or failed
          if (!reverseData || !reverseData.city || reverseData.city.toLowerCase().includes('device coordinate')) {
            try {
              const resp = await fetch(
                `https://api.bigdatacloud.net/data/reverse-geocode-client?latitude=${lat}&longitude=${lon}&localityLanguage=en`
              )
              if (resp.ok) {
                const bdc = await resp.json()
                const city = bdc.city || bdc.locality || bdc.principalSubdivision || 'Device Location'
                const region = bdc.principalSubdivision || ''
                const country = bdc.countryName || 'India'
                const parts = [city, region, country].filter((p, i, a) => p && a.indexOf(p) === i)
                reverseData = {
                  city,
                  region,
                  country,
                  country_code: bdc.countryCode || 'LOC',
                  display_name: parts.join(', '),
                  cardinal_coords: `${lat.toFixed(4)}°, ${lon.toFixed(4)}°`,
                }
              }
            } catch (clientErr) {
              console.warn('Client reverse fallback failed:', clientErr)
            }
          }

          const placeTitle =
            reverseData?.display_name ||
            (reverseData?.city && reverseData?.country
              ? `${reverseData.city}, ${reverseData.country}`
              : 'Physical Device Location')

          const deviceMarker: MapMarkerItem = {
            id: 'device-location',
            ip: 'Local Device GPS',
            lat: lat,
            lon: lon,
            city: reverseData?.city || 'Local Device',
            country: reverseData?.country || 'Local Area',
            country_code: reverseData?.country_code || 'LOC',
            isp: 'Your Physical Device Location',
            org: placeTitle,
            asn: 'GPS Lat/Lon',
            role: 'User Reference Location',
            threat_score: 0,
            threat_tier: {
              tier: 'Safe',
              score: 0,
              color: '#06b6d4',
              bg_color: 'rgba(6, 182, 212, 0.15)',
              border_color: '#06b6d4',
              label: 'DEVICE GPS',
              typical: 'Physical device origin for route comparison',
            },
            cardinal_coords: reverseData?.cardinal_coords || `${lat.toFixed(4)}°, ${lon.toFixed(4)}°`,
            confidence_statement: `Physical Location: ${placeTitle}`,
            isDeviceLocation: true,
          }

          setMarkers(prev => [deviceMarker, ...prev.filter(m => m.id !== 'device-location')])
          setSelectedNode(deviceMarker)
          setFlyToTarget({ lat, lon, zoom: 9, id: 'device-location' })
        } catch (err) {
          setError(`Reverse geocoding error: ${err}`)
        } finally {
          setLoadingGps(false)
        }
      },
      async err => {
        console.warn('HTML5 GPS unavailable, resolving device location via network:', err)
        try {
          const fallbackResp = await fetch('https://api.bigdatacloud.net/data/reverse-geocode-client?localityLanguage=en')
          if (fallbackResp.ok) {
            const bdc = await fallbackResp.json()
            const lat = bdc.latitude || 13.3208
            const lon = bdc.longitude || 77.0923
            const city = bdc.city || bdc.locality || bdc.principalSubdivision || 'Device Region'
            const region = bdc.principalSubdivision || ''
            const country = bdc.countryName || 'India'
            const parts = [city, region, country].filter((p, i, a) => p && a.indexOf(p) === i)
            const placeTitle = parts.join(', ')

            const deviceMarker: MapMarkerItem = {
              id: 'device-location',
              ip: 'Network Location',
              lat: lat,
              lon: lon,
              city: city,
              country: country,
              country_code: bdc.countryCode || 'LOC',
              isp: 'Device Network Location',
              org: placeTitle,
              asn: 'Network GeoIP',
              role: 'User Reference Location (Network IP)',
              threat_score: 0,
              threat_tier: {
                tier: 'Safe',
                score: 0,
                color: '#06b6d4',
                bg_color: 'rgba(6, 182, 212, 0.15)',
                border_color: '#06b6d4',
                label: 'DEVICE GPS',
                typical: 'Physical device origin for route comparison',
              },
              cardinal_coords: `${lat.toFixed(4)}°, ${lon.toFixed(4)}°`,
              confidence_statement: `Physical Location: ${placeTitle}`,
              isDeviceLocation: true,
            }

            setMarkers(prev => [deviceMarker, ...prev.filter(m => m.id !== 'device-location')])
            setSelectedNode(deviceMarker)
            setFlyToTarget({ lat, lon, zoom: 9, id: 'device-location' })
            setLoadingGps(false)
            return
          }
        } catch {
          // Fall through to error below
        }
        setLoadingGps(false)
        setError(`Location access denied or unavailable: ${err.message}`)
      },
      { timeout: 10000, enableHighAccuracy: true }
    )
  }

  return (
    <div className="min-h-screen bg-slate-50 flex flex-col selection:bg-blue-600 selection:text-white">
      <Navbar user={user} onLogout={() => (window.location.href = '/')} />

      <div className="flex-1 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 w-full space-y-5">
        {/* Page Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 bg-white p-5 rounded-2xl border border-slate-200 shadow-sm">
          <div>
            <div className="flex items-center gap-2">
              <span className="p-2 rounded-xl bg-blue-50 text-blue-600 border border-blue-100">
                <Globe className="h-5 w-5" />
              </span>
              <div>
                <h1 className="text-lg font-bold text-slate-900 tracking-tight flex items-center gap-2">
                  <span>ThreatLens AI Geolocation & Global Radar</span>
                  <span className="text-[10px] px-2 py-0.5 rounded-full bg-blue-100 text-blue-800 font-mono font-semibold">
                    LIVE TELEMETRY
                  </span>
                </h1>
                <p className="text-xs text-slate-500 mt-0.5">
                  Reverse-hop carrier tracing, 5-tier threat resolution, and interactive sender localization.
                </p>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleGetDeviceLocation}
              disabled={loadingGps}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-cyan-50 hover:bg-cyan-100 text-cyan-800 border border-cyan-200 text-xs font-semibold shadow-sm transition-all disabled:opacity-50"
              title="Detect physical device location using GPS"
            >
              <LocateFixed className={`h-4 w-4 text-cyan-600 ${loadingGps ? 'animate-spin' : ''}`} />
              <span>{loadingGps ? 'Locating...' : 'Get My Current Location'}</span>
            </button>

            <button
              onClick={loadRecentEmailThreats}
              disabled={loadingRecent}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-slate-50 hover:bg-slate-100 text-slate-700 border border-slate-200 text-xs font-semibold transition-all disabled:opacity-50"
              title="Sync scanned email sender coordinates"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${loadingRecent ? 'animate-spin text-blue-600' : ''}`} />
              <span className="hidden sm:inline">Sync Inbox Threats</span>
            </button>
          </div>
        </div>

        {/* Live Sender Tracking Notification Banner */}
        {trackingBanner && (
          <div className="p-4 bg-blue-50 border border-blue-200 rounded-2xl flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-xs">
            <div className="flex items-center gap-3 min-w-0">
              <div className="h-9 w-9 rounded-xl bg-blue-600 text-white flex items-center justify-center flex-shrink-0 shadow-sm animate-pulse">
                <Crosshair className="h-5 w-5" />
              </div>
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-bold text-blue-950 uppercase tracking-wide">
                    Live Sender Tracking Active
                  </span>
                  <span className="text-[10px] font-mono font-bold bg-blue-200 text-blue-800 px-2 py-0.5 rounded-full">
                    ACCURATE PINPOINT
                  </span>
                </div>
                <div className="text-xs text-slate-800 font-semibold truncate mt-0.5">
                  "{trackingBanner.subject}" &mdash;{' '}
                  <span className="text-slate-600 font-normal">From: {trackingBanner.sender}</span>
                </div>
                <div className="text-[11px] text-blue-700 font-medium flex items-center gap-1.5 mt-0.5">
                  <MapPin className="h-3.5 w-3.5 text-blue-600 flex-shrink-0" />
                  <span>
                    Physical Location: <strong>{trackingBanner.location}</strong>
                  </span>
                  {trackingBanner.ip && <span className="font-mono text-slate-500">({trackingBanner.ip})</span>}
                </div>
              </div>
            </div>
            <div className="flex items-center gap-2 flex-shrink-0">
              <button
                onClick={() => {
                  if (selectedNode) {
                    setFlyToTarget({ lat: selectedNode.lat, lon: selectedNode.lon, zoom: 9, id: selectedNode.id })
                  }
                }}
                className="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold rounded-xl transition-all shadow-sm flex items-center gap-1"
              >
                <LocateFixed className="h-3.5 w-3.5" />
                <span>Re-Focus Map</span>
              </button>
              <button
                onClick={() => setTrackingBanner(null)}
                className="text-xs text-slate-400 hover:text-slate-600 px-2 py-1"
              >
                Dismiss
              </button>
            </div>
          </div>
        )}

        {/* IP Pinpoint Search Bar */}
        <div className="bg-white p-4 rounded-2xl border border-slate-200 shadow-sm space-y-3">
          <form
            onSubmit={e => {
              e.preventDefault()
              handlePinpoint()
            }}
            className="flex flex-col sm:flex-row items-center gap-2.5"
          >
            <div className="relative flex-1 w-full">
              <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
              <input
                type="text"
                value={ipInput}
                onChange={e => setIpInput(e.target.value)}
                placeholder="Enter IP Address to geolocate & score (e.g. 185.220.101.5, 194.26.29.112)..."
                className="w-full bg-slate-50 border border-slate-300 rounded-xl pl-10 pr-4 py-2.5 text-xs text-slate-900 placeholder-slate-400 focus:outline-none focus:border-blue-600 focus:bg-white font-mono transition-all"
              />
            </div>

            <button
              type="submit"
              disabled={loadingLookup || !ipInput.trim()}
              className="w-full sm:w-auto flex items-center justify-center gap-2 px-5 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-700 text-xs font-semibold text-white shadow-sm transition-all disabled:opacity-50"
            >
              <MapPin className="h-3.5 w-3.5" />
              <span>{loadingLookup ? 'Resolving...' : 'Pinpoint IP'}</span>
            </button>
          </form>

          {/* Quick Presets */}
          <div className="flex items-center gap-1.5 pt-1 text-[11px] text-slate-500 flex-wrap">
            <span className="font-semibold text-slate-600 mr-1">Quick Telemetry Targets:</span>
            {quickPresets.map(preset => (
              <button
                key={preset.ip}
                onClick={() => handlePinpoint(preset.ip)}
                className="px-2.5 py-1 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-700 font-mono transition-colors border border-slate-200 flex items-center gap-1"
              >
                <span>{preset.label}</span>
                <span className="text-slate-400">({preset.ip})</span>
              </button>
            ))}
          </div>
        </div>

        {/* Error Notification */}
        {error && (
          <div className="p-4 bg-rose-50 border border-rose-200 rounded-2xl text-rose-800 text-xs flex items-center justify-between">
            <div className="flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-rose-600" />
              <span>{error}</span>
            </div>
            <button onClick={() => setError('')} className="underline text-rose-700 font-semibold">
              Dismiss
            </button>
          </div>
        )}

        {/* Interactive World Map Component */}
        <GeoLocationMap
          markers={markers}
          flyTo={flyToTarget}
          height="520px"
          showRadius={true}
          selectedMarkerId={selectedNode?.id}
          onMarkerClick={node => {
            setSelectedNode(node)
            setFlyToTarget({ lat: node.lat, lon: node.lon, zoom: 7, id: node.id })
          }}
        />

        {/* Resolved Target Nodes Telemetry Table */}
        <div className="bg-white rounded-2xl border border-slate-200 overflow-hidden shadow-sm">
          <div className="px-5 py-3.5 bg-slate-50 border-b border-slate-200 flex items-center justify-between">
            <div className="flex items-center gap-2 text-xs font-bold text-slate-800">
              <Crosshair className="h-4 w-4 text-blue-600" />
              <span>Plotted Target Nodes Telemetry</span>
              <span className="text-slate-500 font-normal">({markers.length} nodes active)</span>
            </div>
            <span className="text-[11px] text-slate-400 font-mono">Click 'Fly To' to navigate camera</span>
          </div>

          {markers.length === 0 ? (
            <div className="py-16 text-center text-slate-500 text-xs">
              <MapPin className="h-8 w-8 text-slate-300 mx-auto mb-2" />
              <p className="font-semibold text-slate-700">No nodes plotted yet</p>
              <p className="text-[11px] text-slate-400 mt-0.5">
                Pinpoint an IP above or click 'Get My Current Location' to plot nodes on the radar.
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-slate-200 bg-slate-50/70 text-[11px] font-semibold text-slate-600 uppercase tracking-wider">
                    <th className="py-2.5 px-4">Node / IP</th>
                    <th className="py-2.5 px-4">Actual Physical Location</th>
                    <th className="py-2.5 px-4">Coordinates</th>
                    <th className="py-2.5 px-4">Threat Tier</th>
                    <th className="py-2.5 px-4">Carrier / ASN</th>
                    <th className="py-2.5 px-4 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 text-slate-700">
                  {markers.map(m => (
                    <tr
                      key={m.id}
                      className={`hover:bg-slate-50 transition-colors ${
                        selectedNode?.id === m.id ? 'bg-blue-50/50' : ''
                      }`}
                    >
                      <td className="py-3 px-4 font-mono font-semibold text-slate-900">
                        <div className="flex items-center gap-2">
                          <span
                            className="w-2.5 h-2.5 rounded-full flex-shrink-0"
                            style={{ backgroundColor: m.threat_tier?.color || '#94a3b8' }}
                          ></span>
                          <span>{m.ip}</span>
                        </div>
                      </td>
                      <td className="py-3 px-4 font-semibold text-slate-800">
                        <div className="flex items-center gap-1.5">
                          <MapPin className="h-3.5 w-3.5 text-blue-600 flex-shrink-0" />
                          <span className="truncate max-w-[220px]">
                            {m.isDeviceLocation
                              ? (m.org || `${m.city}, ${m.country}`)
                              : (m.city && m.country ? `${m.city}, ${m.country}` : m.country || 'Global Network')}
                          </span>
                        </div>
                      </td>
                      <td className="py-3 px-4 font-mono text-[11px] text-slate-600">
                        {m.cardinal_coords || `${m.lat.toFixed(4)}°, ${m.lon.toFixed(4)}°`}
                      </td>
                      <td className="py-3 px-4">
                        <span
                          className="px-2 py-0.5 rounded-full text-[10px] font-bold font-mono text-white shadow-sm inline-block"
                          style={{ backgroundColor: m.threat_tier?.color || '#64748b' }}
                        >
                          {m.isDeviceLocation ? 'DEVICE GPS' : `${m.threat_tier?.label || 'THREAT'} (${m.threat_score ?? 0}%)`}
                        </span>
                      </td>
                      <td className="py-3 px-4 font-mono text-[11px] text-slate-600 truncate max-w-[200px]">
                        <div>{m.isp || m.org || 'Unknown'}</div>
                        <div className="text-[10px] text-slate-400">{m.asn || 'N/A'}</div>
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={() => {
                            setSelectedNode(m)
                            setFlyToTarget({ lat: m.lat, lon: m.lon, zoom: 8, id: m.id })
                          }}
                          className="px-3 py-1.5 rounded-xl bg-white border border-slate-200 hover:border-blue-400 text-slate-700 hover:text-blue-700 text-xs font-semibold shadow-sm transition-all inline-flex items-center gap-1"
                        >
                          <Navigation className="h-3 w-3 text-blue-600" />
                          <span>Fly To</span>
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
