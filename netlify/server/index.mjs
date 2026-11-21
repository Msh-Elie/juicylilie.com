// Vérification Cloudflare Turnstile côté serveur.
// La clé secrète est lue uniquement depuis la variable d'environnement
// TURNSTILE_SECRET_KEY et n'est jamais envoyée au navigateur.

const SITEVERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify'

// Les destinations finales ne sont révélées qu'après une validation réussie.
const DESTINATIONS = {
  of: 'https://onlyfans.com/juicy_lilie/c57',
}

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
    },
  })

async function verify(request, context) {
  if (request.method !== 'POST') {
    return json({ success: false, error: 'Méthode non autorisée.' }, 405)
  }

  const secret = process.env.TURNSTILE_SECRET_KEY
  if (!secret) {
    console.error('TURNSTILE_SECRET_KEY is not configured')
    return json({ success: false, error: 'La vérification est momentanément indisponible.' }, 500)
  }

  let payload
  try {
    payload = await request.json()
  } catch {
    return json({ success: false, error: 'Requête invalide.' }, 400)
  }

  const token = typeof payload?.token === 'string' ? payload.token : ''
  const target = typeof payload?.target === 'string' ? payload.target : ''
  const destination = DESTINATIONS[target]

  if (!destination) {
    return json({ success: false, error: 'Destination inconnue.' }, 400)
  }
  if (!token || token.length > 2048) {
    return json({ success: false, error: 'Jeton de vérification manquant ou invalide.' }, 400)
  }

  const form = new URLSearchParams()
  form.set('secret', secret)
  form.set('response', token)
  const ip =
    context?.ip ||
    request.headers.get('x-nf-client-connection-ip') ||
    request.headers.get('cf-connecting-ip')
  if (ip) form.set('remoteip', ip)
  form.set('idempotency_key', crypto.randomUUID())

  let outcome
  try {
    const res = await fetch(SITEVERIFY_URL, {
      method: 'POST',
      body: form,
      signal: AbortSignal.timeout(8000),
    })
    outcome = await res.json()
  } catch (err) {
    console.error('Siteverify request failed', err)
    return json({ success: false, error: 'Impossible de contacter le service de vérification. Réessaie.' }, 502)
  }

  if (!outcome?.success) {
    console.warn('Turnstile verification failed', outcome?.['error-codes'])
    return json(
      {
        success: false,
        error: 'La vérification a échoué ou a expiré. Merci de réessayer.',
        codes: outcome?.['error-codes'] || [],
      },
      403,
    )
  }

  return json({ success: true, url: destination })
}

export default async function handler(request, context) {
  const { pathname } = new URL(request.url)
  if (pathname === '/api/verify-turnstile') {
    return verify(request, context)
  }
  return json({ error: 'Not found' }, 404)
}

export const config = {
  path: '/api/*',
}
