<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Illuminate\Support\Facades\Log;

use App\Models\UserToken;

use PHPOpenSourceSaver\JWTAuth\Facades\JWTAuth;
use PHPOpenSourceSaver\JWTAuth\Exceptions\TokenExpiredException;
use PHPOpenSourceSaver\JWTAuth\Exceptions\TokenInvalidException;
use PHPOpenSourceSaver\JWTAuth\Exceptions\JWTException;


class JwtSecurityMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        try {
            // Récupérer le payload du token
            $payload = JWTAuth::parseToken()->getPayload();
            $jti = $payload->get('jti');
            $user_id = $payload->get('sub');

            // Vérifier si le token existe en DB
            $token_record = UserToken::where('jti', $jti)
                ->where('user_id', $user_id)
                ->first();

            if (!$token_record) {
                return response()->json([
                    'status' => 'error',
                    'message' => 'Token non autorisé ou révoqué'
                ], 401);
            }

            // Vérifier l'expiration
            if ($token_record->isExpired()) {
                $token_record->delete();
                return response()->json([
                    'status' => 'error',
                    'message' => 'Session expirée'
                ], 401);
            }

            // Vérification IP (optionnel - peut être strict selon vos besoins)
            if ($token_record->ip_address !== $request->ip()) {
                Log::warning('IP mismatch détectée', [
                    'user_id' => $user_id,
                    'jti' => $jti,
                    'expected_ip' => $token_record->ip_address,
                    'actual_ip' => $request->ip(),
                    'user_agent' => $request->userAgent()
                ]);
            }

            // Mettre à jour last_used_at
            $token_record->update(['last_used_at' => now()]);

        } catch (TokenExpiredException $e) {
            return response()->json([
                'status' => 'error',
                'message' => 'Token expiré'
            ], 401);
        } catch (TokenInvalidException $e) {
            return response()->json([
                'status' => 'error',
                'message' => 'Token invalide'
            ], 401);
        } catch (JWTException $e) {
            return response()->json([
                'status' => 'error',
                'message' => 'Token absent'
            ], 401);
        } catch (\Exception $e) {
            Log::error('JwtSecurityMiddleware error', [
                'message' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            return response()->json([
                'status' => 'error',
                'message' => 'Erreur d\'authentification'
            ], 401);
        }

        return $next($request);
    }
}
