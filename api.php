<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

use App\Http\Controllers\AuthController;
use App\Http\Controllers\RoleController;
use App\Http\Controllers\UserController;
use App\Http\Controllers\GarantieController;
use App\Http\Controllers\TypeGarantieController;
use App\Http\Controllers\TypeOperationController;
use App\Http\Controllers\TypeAnomalieController;
use App\Http\Controllers\ChecklistController;
use App\Http\Controllers\InventaireController;
use App\Http\Controllers\ControleController;
use App\Http\Controllers\MainLeveeController;
use App\Http\Controllers\HomeController;



Route::post('login', [AuthController::class, 'login']);

Route::post('/refresh', [AuthController::class, 'refresh'])->middleware('jwt.refresh');

Route::get('/inventaires/export', [InventaireController::class, 'export']);


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

    // ---------------- Garantie -----------------------
    Route::resource('garanties', GarantieController::class);
    Route::post('garanties/import', [GarantieController::class, 'import']);

    // ---------------- Type Garantie -----------------------
    Route::resource('type_garanties', TypeGarantieController::class);

    // ---------------- Type Operation -----------------------
    Route::resource('type_operations', TypeOperationController::class);

    // ---------------- Type Anomalie -----------------------
    Route::resource('type_anomalies', TypeAnomalieController::class);

    // ---------------- Checklist -----------------------
    Route::get('checklists/{type_operation_id?}/{type_garantie_id?}', [ChecklistController::class, 'index'])->whereNumber(['type_operation_id', 'type_garantie_id']);
    Route::post('checklists', [ChecklistController::class, 'store']);
    Route::delete('checklists/{uuid}', [ChecklistController::class, 'destroy']);

    // ---------------- Inventaire -----------------------
    Route::get('inventaires/{per_page?}', [InventaireController::class, 'index'])->whereNumber(['per_page']);
    Route::resource('inventaires', InventaireController::class);
    // Route::get('/inventaires/export', [InventaireController::class, 'export']);

    // ---------------- Controle -----------------------
    Route::get('controles/{per_page?}', [ControleController::class, 'index'])->whereNumber(['per_page']);
    Route::resource('controles', ControleController::class);

    // ---------------- Main levee -----------------------
    Route::get('main_levees/{per_page?}', [MainLeveeController::class, 'index'])->whereNumber(['per_page']);
    Route::resource('main_levees', MainLeveeController::class);

    // ---------------- Role ----------
    Route::prefix('roles')->group(function () {
        Route::get('/', [RoleController::class, 'index']);
        Route::get('/{id}', [RoleController::class, 'show']);
        Route::post('/', [RoleController::class, 'store']);
        Route::put('/{id}', [RoleController::class, 'update']);
        Route::delete('/{id}', [RoleController::class, 'destroy']);
        Route::get('/{id}/permissions', [RoleController::class, 'get_role_permissions']);
        Route::post('/{id}/permissions', [RoleController::class, 'update_role_permissions']);
    });

    // ---------------- Permission ----------
    Route::prefix('permissions')->group(function () {
        Route::get('/', [RoleController::class, 'get_permissions']);
        Route::post('/', [RoleController::class, 'store_permission']);
        Route::put('/{id}', [RoleController::class, 'update_permission']);
        Route::delete('/{id}', [RoleController::class, 'destroy_permission']);
    });

    // ---------------- Stats -----------------------
    Route::get('stats', [HomeController::class, 'index']);
    Route::get('historique/{uuid}', [HomeController::class, 'historique']);
});


