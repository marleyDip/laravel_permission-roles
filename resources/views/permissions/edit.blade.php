<x-app-layout>
    <x-slot name="header">
        <div class="flex justify-between">
            <h2 class="font-semibold text-xl text-gray-800 leading-tight">
                Permissions / Edit
            </h2>
            <a href="{{ route('permissions.index') }}" class="bg-slate-700 text-sm rounded-md text-white px-3 py-2">Back</a>
        </div>
    </x-slot>

    <div class="py-12">
        <div class="max-w-7xl mx-auto sm:px-6 lg:px-8">
            <div class="bg-white overflow-hidden shadow-sm sm:rounded-lg">
                <div class="p-6 text-gray-900">
                    <form action="{{ route('permissions.update',$permission->id) }}" method="post">
                        @csrf
                        <div>
                            <label for="" class="text-lg font-medium">Name</label>
                            <div class="my-3">
                                <input value="{{ old('name', $permission->name) }}" name="name" placeholder="Enter Name" type="text" class="border-gray-300 shadow-sm w-1/2 rounded-lg">

                                @error('name')
                                <p class="text-red-400 font-medium">{{ $message }}</p>
                                @enderror

                            </div>
                            <button class="bg-slate-700 hover:bg-slate-600 text-sm rounded-md text-white px-5 py-3">Update</button>
                        </div>
                    </form>

                </div>
            </div>
        </div>
    </div>
</x-app-layout>
