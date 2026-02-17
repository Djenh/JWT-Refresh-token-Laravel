<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

use App\Http\Controllers\AuthController;
use App\Http\Controllers\UserController;



Route::post('login', [AuthController::class, 'login']);

Route::post('/refresh', [AuthController::class, 'refresh'])->middleware('jwt.refresh');


Route::middleware(['auth:api', 'jwt.security'])->group(function () {
    // ---------------- User -----------------------
    Route::get('users', [UserController::class, 'index']);
    Route::get('profile', [UserController::class, 'get_profile']);
    Route::post('register', [UserController::class, 'register']);
    Route::put('users/update/{uuid}', [UserController::class, 'update_credentials']);
    Route::put('users/update_password', [UserController::class, 'update_password']);
    Route::post('logout', [UserController::class, 'logout']);
    Route::post('logout_all', [UserController::class, 'logout_all']);
    Route::get('users/sessions', [UserController::class, 'get_active_sessions']);
    Route::delete('users/sessions/{jti}', [UserController::class, 'revoke_session']);
    
});


