<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\AdminController;
use App\Http\Controllers\ProfileController;
use App\Http\Middleware\EnsureFrontendRequestsAreStateful;
use App\Http\Controllers\admin\ProfileController as AdminProfileController;
use App\Http\Controllers\manager\ProfileController as ManagerProfileController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

// Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
//     return $request->user();
// });

Route::post('/signup', [AuthController::class, 'signup']);
Route::post('/login', [AuthController::class, 'login']);
Route::get('/logout', [AuthController::class, 'logout']);
Route::post('/admin/assign_roles', [AdminController::class, 'assign_roles']);

// Route::group(['middleware' => ['auth:sanctum', EnsureFrontendRequestsAreStateful::class]], function(){
//     Route::get('/dashboard/profile', [ProfileController::class, 'index'])->name('dashboard.profile');
// });

// Route::group(['middleware' => ['auth:sanctum', 'role:user']], function(){
//     Route::get('/dashboard/profile', [ProfileController::class, 'index'])->name('dashboard.profile');
//     Route::post('/logout', [AuthController::class, 'logout']);
// });

// Route::group(['middleware' => ['auth:sanctum', 'role:admin']], function(){
//     Route::get('/admin/dashboard/profile', [AdminProfileController::class, 'index'])->name('admin.dashboard.profile');
//     Route::post('/admin/logout', [AuthController::class, 'logout']);
// });

Route::group(['middleware' => ['auth:sanctum', EnsureFrontendRequestsAreStateful::class, 'role:user']], function () {
    Route::get('/dashboard/profile', [ProfileController::class, 'index'])->name('dashboard.profile');
    Route::post('/logout', [AuthController::class, 'logout']);
});


Route::group(['middleware' => ['auth:sanctum', 'role:manager']], function(){
    Route::get('/manager/dashboard/profile', [ManagerProfileController::class, 'index'])->name('manager.dashboard.profile');
    Route::post('/manager/logout', [AuthController::class, 'logout']);
});