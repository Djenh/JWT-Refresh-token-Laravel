<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

use Illuminate\Support\Facades\Log;
use PHPOpenSourceSaver\JWTAuth\Facades\JWTAuth;
use PHPOpenSourceSaver\JWTAuth\Exceptions\TokenExpiredException;
use PHPOpenSourceSaver\JWTAuth\Exceptions\TokenInvalidException;
use PHPOpenSourceSaver\JWTAuth\Exceptions\JWTException;


class JwtRefreshMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        try {
            JWTAuth::parseToken();

            // Si on arrive ici, le token existe et a une signature valide (peu importe s'il est expiré ou non)
            return $next($request);

        } catch (TokenExpiredException $e) {
            // Token expiré, C'est OK pour le refresh ! on laisse passer pour que la méthode refresh() puisse le traiter
            return $next($request);

        } catch (TokenInvalidException $e) {
            // Token invalide (signature incorrecte, format invalide, etc.)
            return response()->json([
                'status' => 'error',
                'message' => 'Token invalide'
            ], 401);

        } catch (JWTException $e) {
            // Pas de token du tout
            return response()->json([
                'status' => 'error',
                'message' => 'Token absent'
            ], 401);

        } catch (\Exception $e) {
            Log::error('JwtRefreshMiddleware error', [
                'message' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);

            return response()->json([
                'status' => 'error',
                'message' => 'Erreur d\'authentification'
            ], 401);
        }
    }
}
