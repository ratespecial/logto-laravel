<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        $column = config('logto.subject-column');

        Schema::table('users', function (Blueprint $table) use ($column) {
            $table->string($column)->nullable()->unique()->after('email');
        });
    }

    public function down(): void
    {
        $column = config('logto.subject-column');

        Schema::table('users', function (Blueprint $table) use ($column) {
            $table->dropUnique([$column]);
            $table->dropColumn($column);
        });
    }
};
