// Copyright 2022, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Wrapper around libfdt library. Provides parsing/generating functionality
//! to a bare-metal environment.

#![no_std]

mod iterators;
mod libfdt;
mod result;

pub use iterators::{
    AddressRange, CellIterator, CompatibleIterator, DescendantsIterator, MemRegIterator,
    PropertyIterator, RangesIterator, Reg, RegIterator, SubnodeIterator,
};
pub use result::{FdtError, Result};

use core::ffi::{c_int, c_void, CStr};
use core::ops::Range;
use core::ptr;
use cstr::cstr;
use result::{fdt_err, fdt_err_expect_zero, fdt_err_or_option};
use zerocopy::AsBytes as _;

/// Value of a #address-cells property.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum AddrCells {
    Single = 1,
    Double = 2,
    Triple = 3,
}

impl TryFrom<usize> for AddrCells {
    type Error = FdtError;

    fn try_from(value: usize) -> Result<Self> {
        match value {
            x if x == Self::Single as _ => Ok(Self::Single),
            x if x == Self::Double as _ => Ok(Self::Double),
            x if x == Self::Triple as _ => Ok(Self::Triple),
            _ => Err(FdtError::BadNCells),
        }
    }
}

/// Value of a #size-cells property.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum SizeCells {
    None = 0,
    Single = 1,
    Double = 2,
}

impl TryFrom<usize> for SizeCells {
    type Error = FdtError;

    fn try_from(value: usize) -> Result<Self> {
        match value {
            x if x == Self::None as _ => Ok(Self::None),
            x if x == Self::Single as _ => Ok(Self::Single),
            x if x == Self::Double as _ => Ok(Self::Double),
            _ => Err(FdtError::BadNCells),
        }
    }
}

/// DT property wrapper to abstract endianess changes
#[repr(transparent)]
#[derive(Debug)]
struct FdtPropertyStruct(libfdt_bindgen::fdt_property);

impl AsRef<FdtPropertyStruct> for libfdt_bindgen::fdt_property {
    fn as_ref(&self) -> &FdtPropertyStruct {
        let ptr = self as *const _ as *const _;
        // SAFETY: Types have the same layout (transparent) so the valid reference remains valid.
        unsafe { &*ptr }
    }
}

impl FdtPropertyStruct {
    fn from_offset(fdt: &Fdt, offset: c_int) -> Result<&Self> {
        let mut len = 0;
        let prop =
            // SAFETY: Accesses (read-only) are constrained to the DT totalsize.
            unsafe { libfdt_bindgen::fdt_get_property_by_offset(fdt.as_ptr(), offset, &mut len) };
        if prop.is_null() {
            fdt_err(len)?;
            return Err(FdtError::Internal); // shouldn't happen.
        }
        // SAFETY: prop is only returned when it points to valid libfdt_bindgen.
        let prop = unsafe { &*prop };
        Ok(prop.as_ref())
    }

    fn name_offset(&self) -> c_int {
        u32::from_be(self.0.nameoff).try_into().unwrap()
    }

    fn data_len(&self) -> usize {
        u32::from_be(self.0.len).try_into().unwrap()
    }

    fn data_ptr(&self) -> *const c_void {
        self.0.data.as_ptr().cast()
    }
}

/// DT property.
#[derive(Clone, Copy, Debug)]
pub struct FdtProperty<'a> {
    fdt: &'a Fdt,
    offset: c_int,
    property: &'a FdtPropertyStruct,
}

impl<'a> FdtProperty<'a> {
    fn new(fdt: &'a Fdt, offset: c_int) -> Result<Self> {
        let property = FdtPropertyStruct::from_offset(fdt, offset)?;
        Ok(Self { fdt, offset, property })
    }

    /// Returns the property name
    pub fn name(&self) -> Result<&'a CStr> {
        self.fdt.string(self.property.name_offset())
    }

    /// Returns the property value
    pub fn value(&self) -> Result<&'a [u8]> {
        self.fdt.get_from_ptr(self.property.data_ptr(), self.property.data_len())
    }

    fn next_property(&self) -> Result<Option<Self>> {
        let ret =
            // SAFETY: Accesses (read-only) are constrained to the DT totalsize.
            unsafe { libfdt_bindgen::fdt_next_property_offset(self.fdt.as_ptr(), self.offset) };

        if let Some(offset) = fdt_err_or_option(ret)? {
            Ok(Some(Self::new(self.fdt, offset)?))
        } else {
            Ok(None)
        }
    }
}

/// DT node.
#[derive(Clone, Copy, Debug)]
pub struct FdtNode<'a> {
    fdt: &'a Fdt,
    offset: c_int,
}

impl<'a> FdtNode<'a> {
    /// Returns parent node.
    pub fn parent(&self) -> Result<Self> {
        // SAFETY: Accesses (read-only) are constrained to the DT totalsize.
        let ret = unsafe { libfdt_bindgen::fdt_parent_offset(self.fdt.as_ptr(), self.offset) };
        let offset = fdt_err(ret)?;

        Ok(Self { fdt: self.fdt, offset })
    }

    /// Returns supernode with depth. Note that root is at depth 0.
    pub fn supernode_at_depth(&self, depth: usize) -> Result<Self> {
        // SAFETY: Accesses (read-only) are constrained to the DT totalsize.
        let ret = unsafe {
            libfdt_bindgen::fdt_supernode_atdepth_offset(
                self.fdt.as_ptr(),
                self.offset,
                depth.try_into().unwrap(),
                ptr::null_mut(),
            )
        };
        let offset = fdt_err(ret)?;

        Ok(Self { fdt: self.fdt, offset })
    }

    /// Returns the standard (deprecated) device_type <string> property.
    pub fn device_type(&self) -> Result<Option<&CStr>> {
        self.getprop_str(cstr!("device_type"))
    }

    /// Returns the standard reg <prop-encoded-array> property.
    pub fn reg(&self) -> Result<Option<RegIterator<'a>>> {
        if let Some(cells) = self.getprop_cells(cstr!("reg"))? {
            let parent = self.parent()?;

            let addr_cells = parent.address_cells()?;
            let size_cells = parent.size_cells()?;

            Ok(Some(RegIterator::new(cells, addr_cells, size_cells)))
        } else {
            Ok(None)
        }
    }

    /// Returns the standard ranges property.
    pub fn ranges<A, P, S>(&self) -> Result<Option<RangesIterator<'a, A, P, S>>> {
        if let Some(cells) = self.getprop_cells(cstr!("ranges"))? {
            let parent = self.parent()?;
            let addr_cells = self.address_cells()?;
            let parent_addr_cells = parent.address_cells()?;
            let size_cells = self.size_cells()?;
            Ok(Some(RangesIterator::<A, P, S>::new(
                cells,
                addr_cells,
                parent_addr_cells,
                size_cells,
            )))
        } else {
            Ok(None)
        }
    }

    /// Returns the node name.
    pub fn name(&self) -> Result<&'a CStr> {
        let mut len: c_int = 0;
        // SAFETY: Accesses are constrained to the DT totalsize (validated by ctor). On success, the
        // function returns valid null terminating string and otherwise returned values are dropped.
        let name = unsafe { libfdt_bindgen::fdt_get_name(self.fdt.as_ptr(), self.offset, &mut len) }
            as *const c_void;
        let len = usize::try_from(fdt_err(len)?).unwrap();
        let name = self.fdt.get_from_ptr(name, len + 1)?;
        CStr::from_bytes_with_nul(name).map_err(|_| FdtError::Internal)
    }

    /// Returns the value of a given <string> property.
    pub fn getprop_str(&self, name: &CStr) -> Result<Option<&CStr>> {
        if let Some(bytes) = self.getprop(name)? {
            Ok(Some(CStr::from_bytes_with_nul(bytes).map_err(|_| FdtError::BadValue)?))
        } else {
            Ok(None)
        }
    }

    /// Returns the value of a given property as an array of cells.
    pub fn getprop_cells(&self, name: &CStr) -> Result<Option<CellIterator<'a>>> {
        if let Some(cells) = self.getprop(name)? {
            Ok(Some(CellIterator::new(cells)))
        } else {
            Ok(None)
        }
    }

    /// Returns the value of a given <u32> property.
    pub fn getprop_u32(&self, name: &CStr) -> Result<Option<u32>> {
        if let Some(bytes) = self.getprop(name)? {
            Ok(Some(u32::from_be_bytes(bytes.try_into().map_err(|_| FdtError::BadValue)?)))
        } else {
            Ok(None)
        }
    }

    /// Returns the value of a given <u64> property.
    pub fn getprop_u64(&self, name: &CStr) -> Result<Option<u64>> {
        if let Some(bytes) = self.getprop(name)? {
            Ok(Some(u64::from_be_bytes(bytes.try_into().map_err(|_| FdtError::BadValue)?)))
        } else {
            Ok(None)
        }
    }

    /// Returns the value of a given property.
    pub fn getprop(&self, name: &CStr) -> Result<Option<&'a [u8]>> {
        if let Some((prop, len)) = Self::getprop_internal(self.fdt, self.offset, name)? {
            Ok(Some(self.fdt.get_from_ptr(prop, len)?))
        } else {
            Ok(None)
        }
    }

    /// Returns the pointer and size of the property named `name`, in a node at offset `offset`, in
    /// a device tree `fdt`. The pointer is guaranteed to be non-null, in which case error returns.
    fn getprop_internal(
        fdt: &'a Fdt,
        offset: c_int,
        name: &CStr,
    ) -> Result<Option<(*const c_void, usize)>> {
        let mut len: i32 = 0;
        // SAFETY: Accesses are constrained to the DT totalsize (validated by ctor) and the
        // function respects the passed number of characters.
        let prop = unsafe {
            libfdt_bindgen::fdt_getprop_namelen(
                fdt.as_ptr(),
                offset,
                name.as_ptr(),
                // *_namelen functions don't include the trailing nul terminator in 'len'.
                name.to_bytes().len().try_into().map_err(|_| FdtError::BadPath)?,
                &mut len as *mut i32,
            )
        } as *const u8;

        let Some(len) = fdt_err_or_option(len)? else {
            return Ok(None); // Property was not found.
        };
        let len = usize::try_from(len).unwrap();

        if prop.is_null() {
            // We expected an error code in len but still received a valid value?!
            return Err(FdtError::Internal);
        }
        Ok(Some((prop.cast::<c_void>(), len)))
    }

    /// Returns reference to the containing device tree.
    pub fn fdt(&self) -> &Fdt {
        self.fdt
    }

    /// Returns the compatible node of the given name that is next after this node.
    pub fn next_compatible(self, compatible: &CStr) -> Result<Option<Self>> {
        // SAFETY: Accesses (read-only) are constrained to the DT totalsize.
        let ret = unsafe {
            libfdt_bindgen::fdt_node_offset_by_compatible(
                self.fdt.as_ptr(),
                self.offset,
                compatible.as_ptr(),
            )
        };
        let offset = fdt_err_or_option(ret)?;

        Ok(offset.map(|offset| Self { fdt: self.fdt, offset }))
    }

    /// Returns the first range of `reg` in this node.
    pub fn first_reg(&self) -> Result<Reg<u64>> {
        self.reg()?.ok_or(FdtError::NotFound)?.next().ok_or(FdtError::NotFound)
    }

    fn address_cells(&self) -> Result<AddrCells> {
        // SAFETY: Accesses are constrained to the DT totalsize (validated by ctor).
        let ret = unsafe { libfdt_bindgen::fdt_address_cells(self.fdt.as_ptr(), self.offset) };

        usize::try_from(ret).map_err(|_| FdtError::Internal)?.try_into()
    }

    fn size_cells(&self) -> Result<SizeCells> {
        // SAFETY: Accesses are constrained to the DT totalsize (validated by ctor).
        let ret = unsafe { libfdt_bindgen::fdt_size_cells(self.fdt.as_ptr(), self.offset) };

        usize::try_from(ret).map_err(|_| FdtError::Internal)?.try_into()
    }

    /// Returns an iterator of subnodes
    pub fn subnodes(&self) -> Result<SubnodeIterator<'a>> {
        SubnodeIterator::new(self)
    }

    fn first_subnode(&self) -> Result<Option<Self>> {
        // SAFETY: Accesses (read-only) are constrained to the DT totalsize.
        let ret = unsafe { libfdt_bindgen::fdt_first_subnode(self.fdt.as_ptr(), self.offset) };
        let offset = fdt_err_or_option(ret)?;

        Ok(offset.map(|offset| Self { fdt: self.fdt, offset }))
    }

    fn next_subnode(&self) -> Result<Option<Self>> {
        // SAFETY: Accesses (read-only) are constrained to the DT totalsize.
        let ret = unsafe { libfdt_bindgen::fdt_next_subnode(self.fdt.as_ptr(), self.offset) };
        let offset = fdt_err_or_option(ret)?;

        Ok(offset.map(|offset| Self { fdt: self.fdt, offset }))
    }

    /// Returns an iterator of descendants
    pub fn descendants(&self) -> DescendantsIterator<'a> {
        DescendantsIterator::new(self)
    }

    fn next_node(&self, depth: usize) -> Result<Option<(Self, usize)>> {
        let mut next_depth: c_int = depth.try_into().unwrap();
        // SAFETY: Accesses (read-only) are constrained to the DT totalsize.
        let ret = unsafe {
            libfdt_bindgen::fdt_next_node(self.fdt.as_ptr(), self.offset, &mut next_depth)
        };
        let Ok(depth) = usize::try_from(next_depth) else {
            return Ok(None);
        };
        if let Some(offset) = fdt_err_or_option(ret)? {
            Ok(Some((Self { fdt: self.fdt, offset }, depth)))
        } else {
            Ok(None)
        }
    }

    /// Returns an iterator of properties
    pub fn properties(&'a self) -> Result<PropertyIterator<'a>> {
        PropertyIterator::new(self)
    }

    fn first_property(&self) -> Result<Option<FdtProperty<'a>>> {
        let ret =
            // SAFETY: Accesses (read-only) are constrained to the DT totalsize.
            unsafe { libfdt_bindgen::fdt_first_property_offset(self.fdt.as_ptr(), self.offset) };

        if let Some(offset) = fdt_err_or_option(ret)? {
            Ok(Some(FdtProperty::new(self.fdt, offset)?))
        } else {
            Ok(None)
        }
    }

    /// Returns the phandle
    pub fn get_phandle(&self) -> Result<Option<Phandle>> {
        // This rewrites the fdt_get_phandle() because it doesn't return error code.
        if let Some(prop) = self.getprop_u32(cstr!("phandle"))? {
            Ok(Some(prop.try_into()?))
        } else if let Some(prop) = self.getprop_u32(cstr!("linux,phandle"))? {
            Ok(Some(prop.try_into()?))
        } else {
            Ok(None)
        }
    }

    /// Returns the subnode of the given name. The name doesn't need to be nul-terminated.
    pub fn subnode(&self, name: &CStr) -> Result<Option<Self>> {
        let name = name.to_bytes();
        let offset = self.subnode_offset(name)?;

        Ok(offset.map(|offset| Self { fdt: self.fdt, offset }))
    }

    /// Returns the subnode of the given name bytes
    pub fn subnode_with_name_bytes(&self, name: &[u8]) -> Result<Option<Self>> {
        let offset = self.subnode_offset(name)?;

        Ok(offset.map(|offset| Self { fdt: self.fdt, offset }))
    }

    fn subnode_offset(&self, name: &[u8]) -> Result<Option<c_int>> {
        let namelen = name.len().try_into().unwrap();
        // SAFETY: Accesses are constrained to the DT totalsize (validated by ctor).
        let ret = unsafe {
            libfdt_bindgen::fdt_subnode_offset_namelen(
                self.fdt.as_ptr(),
                self.offset,
                name.as_ptr().cast::<_>(),
                namelen,
            )
        };
        fdt_err_or_option(ret)
    }
}

impl<'a> PartialEq for FdtNode<'a> {
    fn eq(&self, other: &Self) -> bool {
        self.fdt.as_ptr() == other.fdt.as_ptr() && self.offset == other.offset
    }
}

/// Phandle of a FDT node
#[repr(transparent)]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct Phandle(u32);

impl Phandle {
    /// Minimum valid value for device tree phandles.
    pub const MIN: Self = Self(1);
    /// Maximum valid value for device tree phandles.
    pub const MAX: Self = Self(libfdt_bindgen::FDT_MAX_PHANDLE);

    /// Creates a new Phandle
    pub const fn new(value: u32) -> Option<Self> {
        if Self::MIN.0 <= value && value <= Self::MAX.0 {
            Some(Self(value))
        } else {
            None
        }
    }
}

impl From<Phandle> for u32 {
    fn from(phandle: Phandle) -> u32 {
        phandle.0
    }
}

impl TryFrom<u32> for Phandle {
    type Error = FdtError;

    fn try_from(value: u32) -> Result<Self> {
        Self::new(value).ok_or(FdtError::BadPhandle)
    }
}

/// Mutable FDT node.
#[derive(Debug)]
pub struct FdtNodeMut<'a> {
    fdt: &'a mut Fdt,
    offset: c_int,
}

impl<'a> FdtNodeMut<'a> {
    /// Appends a property name-value (possibly empty) pair to the given node.
    pub fn appendprop<T: AsRef<[u8]>>(&mut self, name: &CStr, value: &T) -> Result<()> {
        // SAFETY: Accesses are constrained to the DT totalsize (validated by ctor).
        let ret = unsafe {
            libfdt_bindgen::fdt_appendprop(
                self.fdt.as_mut_ptr(),
                self.offset,
                name.as_ptr(),
                value.as_ref().as_ptr().cast::<c_void>(),
                value.as_ref().len().try_into().map_err(|_| FdtError::BadValue)?,
            )
        };

        fdt_err_expect_zero(ret)
    }

    /// Appends a (address, size) pair property to the given node.
    pub fn appendprop_addrrange(&mut self, name: &CStr, addr: u64, size: u64) -> Result<()> {
        // SAFETY: Accesses are constrained to the DT totalsize (validated by ctor).
        let ret = unsafe {
            libfdt_bindgen::fdt_appendprop_addrrange(
                self.fdt.as_mut_ptr(),
                self.parent()?.offset,
                self.offset,
                name.as_ptr(),
                addr,
                size,
            )
        };

        fdt_err_expect_zero(ret)
    }

    /// Sets a property name-value pair to the given node.
    ///
    /// This may create a new prop or replace existing value.
    pub fn setprop(&mut self, name: &CStr, value: &[u8]) -> Result<()> {
        // SAFETY: New value size is constrained to the DT totalsize
        //          (validated by underlying libfdt).
        let ret = unsafe {
            libfdt_bindgen::fdt_setprop(
                self.fdt.as_mut_ptr(),
                self.offset,
                name.as_ptr(),
                value.as_ptr().cast::<c_void>(),
                value.len().try_into().map_err(|_| FdtError::BadValue)?,
            )
        };

        fdt_err_expect_zero(ret)
    }

    /// Sets the value of the given property with the given value, and ensure that the given
    /// value has the same length as the current value length.
    ///
    /// This can only be used to replace existing value.
    pub fn setprop_inplace(&mut self, name: &CStr, value: &[u8]) -> Result<()> {
        // SAFETY: fdt size is not altered
        let ret = unsafe {
            libfdt_bindgen::fdt_setprop_inplace(
                self.fdt.as_mut_ptr(),
                self.offset,
                name.as_ptr(),
                value.as_ptr().cast::<c_void>(),
                value.len().try_into().map_err(|_| FdtError::BadValue)?,
            )
        };

        fdt_err_expect_zero(ret)
    }

    /// Sets the value of the given (address, size) pair property with the given value, and
    /// ensure that the given value has the same length as the current value length.
    ///
    /// This can only be used to replace existing value.
    pub fn setprop_addrrange_inplace(&mut self, name: &CStr, addr: u64, size: u64) -> Result<()> {
        let pair = [addr.to_be(), size.to_be()];
        self.setprop_inplace(name, pair.as_bytes())
    }

    /// Sets a flag-like empty property.
    ///
    /// This may create a new prop or replace existing value.
    pub fn setprop_empty(&mut self, name: &CStr) -> Result<()> {
        self.setprop(name, &[])
    }

    /// Deletes the given property.
    pub fn delprop(&mut self, name: &CStr) -> Result<()> {
        // SAFETY: Accesses are constrained to the DT totalsize (validated by ctor) when the
        // library locates the node's property. Removing the property may shift the offsets of
        // other nodes and properties but the borrow checker should prevent this function from
        // being called when FdtNode instances are in use.
        let ret = unsafe {
            libfdt_bindgen::fdt_delprop(self.fdt.as_mut_ptr(), self.offset, name.as_ptr())
        };

        fdt_err_expect_zero(ret)
    }

    /// Deletes the given property effectively from DT, by setting it with FDT_NOP.
    pub fn nop_property(&mut self, name: &CStr) -> Result<()> {
        // SAFETY: Accesses are constrained to the DT totalsize (validated by ctor) when the
        // library locates the node's property.
        let ret = unsafe {
            libfdt_bindgen::fdt_nop_property(self.fdt.as_mut_ptr(), self.offset, name.as_ptr())
        };

        fdt_err_expect_zero(ret)
    }

    /// Trims the size of the given property to new_size.
    pub fn trimprop(&mut self, name: &CStr, new_size: usize) -> Result<()> {
        let (prop, len) =
            FdtNode::getprop_internal(self.fdt, self.offset, name)?.ok_or(FdtError::NotFound)?;
        if len == new_size {
            return Ok(());
        }
        if new_size > len {
            return Err(FdtError::NoSpace);
        }

        // SAFETY: new_size is smaller than the old size
        let ret = unsafe {
            libfdt_bindgen::fdt_setprop(
                self.fdt.as_mut_ptr(),
                self.offset,
                name.as_ptr(),
                prop.cast::<c_void>(),
                new_size.try_into().map_err(|_| FdtError::BadValue)?,
            )
        };

        fdt_err_expect_zero(ret)
    }

    /// Returns reference to the containing device tree.
    pub fn fdt(&mut self) -> &mut Fdt {
        self.fdt
    }

    /// Returns immutable FdtNode of this node.
    pub fn as_node(&self) -> FdtNode {
        FdtNode { fdt: self.fdt, offset: self.offset }
    }

    /// Adds new subnodes to the given node.
    pub fn add_subnodes(&mut self, names: &[&CStr]) -> Result<()> {
        for name in names {
            self.add_subnode_offset(name.to_bytes())?;
        }
        Ok(())
    }

    /// Adds a new subnode to the given node and return it as a FdtNodeMut on success.
    pub fn add_subnode(&'a mut self, name: &CStr) -> Result<Self> {
        let name = name.to_bytes();
        let offset = self.add_subnode_offset(name)?;

        Ok(Self { fdt: self.fdt, offset })
    }

    /// Adds a new subnode to the given node with name and namelen, and returns it as a FdtNodeMut
    /// on success.
    pub fn add_subnode_with_namelen(&'a mut self, name: &CStr, namelen: usize) -> Result<Self> {
        let name = &name.to_bytes()[..namelen];
        let offset = self.add_subnode_offset(name)?;

        Ok(Self { fdt: self.fdt, offset })
    }

    fn add_subnode_offset(&mut self, name: &[u8]) -> Result<c_int> {
        let namelen = name.len().try_into().unwrap();
        // SAFETY: Accesses are constrained to the DT totalsize (validated by ctor).
        let ret = unsafe {
            libfdt_bindgen::fdt_add_subnode_namelen(
                self.fdt.as_mut_ptr(),
                self.offset,
                name.as_ptr().cast::<_>(),
                namelen,
            )
        };
        fdt_err(ret)
    }

    /// Returns the first subnode of this
    pub fn first_subnode(&'a mut self) -> Result<Option<Self>> {
        // SAFETY: Accesses (read-only) are constrained to the DT totalsize.
        let ret = unsafe { libfdt_bindgen::fdt_first_subnode(self.fdt.as_ptr(), self.offset) };
        let offset = fdt_err_or_option(ret)?;

        Ok(offset.map(|offset| Self { fdt: self.fdt, offset }))
    }

    /// Returns the next subnode that shares the same parent with this
    pub fn next_subnode(self) -> Result<Option<Self>> {
        // SAFETY: Accesses (read-only) are constrained to the DT totalsize.
        let ret = unsafe { libfdt_bindgen::fdt_next_subnode(self.fdt.as_ptr(), self.offset) };
        let offset = fdt_err_or_option(ret)?;

        Ok(offset.map(|offset| Self { fdt: self.fdt, offset }))
    }

    /// Deletes the current node and returns the next subnode
    pub fn delete_and_next_subnode(self) -> Result<Option<Self>> {
        // SAFETY: Accesses (read-only) are constrained to the DT totalsize.
        let ret = unsafe { libfdt_bindgen::fdt_next_subnode(self.fdt.as_ptr(), self.offset) };

        let next_offset = fdt_err_or_option(ret)?;

        self.delete_and_next(next_offset)
    }

    fn next_node_offset(&self, depth: usize) -> Result<Option<(c_int, usize)>> {
        let mut next_depth: c_int = depth.try_into().or(Err(FdtError::BadValue))?;
        // SAFETY: Accesses (read-only) are constrained to the DT totalsize.
        let ret = unsafe {
            libfdt_bindgen::fdt_next_node(self.fdt.as_ptr(), self.offset, &mut next_depth)
        };
        let Ok(next_depth) = usize::try_from(next_depth) else {
            return Ok(None);
        };
        Ok(fdt_err_or_option(ret)?.map(|offset| (offset, next_depth)))
    }

    /// Returns the next node
    pub fn next_node(self, depth: usize) -> Result<Option<(Self, usize)>> {
        let next = self.next_node_offset(depth)?;

        Ok(next.map(|(offset, depth)| (Self { fdt: self.fdt, offset }, depth)))
    }

    fn next_node_skip_subnodes(&mut self, depth: usize) -> Result<Option<(c_int, usize)>> {
        let mut iter = self.next_node_offset(depth)?;
        while let Some((descendant_offset, descendant_depth)) = iter {
            if descendant_depth <= depth {
                return Ok(Some((descendant_offset, descendant_depth)));
            }
            let descendant = FdtNodeMut { fdt: self.fdt, offset: descendant_offset };
            iter = descendant.next_node_offset(descendant_depth)?;
        }

        Ok(None)
    }

    /// Deletes this and returns the next node
    pub fn delete_and_next_node(mut self, depth: usize) -> Result<Option<(Self, usize)>> {
        let next_node = self.next_node_skip_subnodes(depth)?;
        if let Some((offset, depth)) = next_node {
            let next_node = self.delete_and_next(Some(offset))?.unwrap();
            Ok(Some((next_node, depth)))
        } else {
            Ok(None)
        }
    }

    fn parent(&'a self) -> Result<FdtNode<'a>> {
        self.as_node().parent()
    }

    /// Returns the compatible node of the given name that is next after this node.
    pub fn next_compatible(self, compatible: &CStr) -> Result<Option<Self>> {
        // SAFETY: Accesses (read-only) are constrained to the DT totalsize.
        let ret = unsafe {
            libfdt_bindgen::fdt_node_offset_by_compatible(
                self.fdt.as_ptr(),
                self.offset,
                compatible.as_ptr(),
            )
        };
        let offset = fdt_err_or_option(ret)?;

        Ok(offset.map(|offset| Self { fdt: self.fdt, offset }))
    }

    /// Deletes the node effectively by overwriting this node and its subtree with nop tags.
    /// Returns the next compatible node of the given name.
    // Side note: without this, filterint out excessive compatible nodes from the DT is impossible.
    // The reason is that libfdt ensures that the node from where the search for the next
    // compatible node is started is always a valid one -- except for the special case of offset =
    // -1 which is to find the first compatible node. So, we can't delete a node and then find the
    // next compatible node from it.
    //
    // We can't do in the opposite direction either. If we call next_compatible to find the next
    // node, and delete the current node, the Rust borrow checker kicks in. The next node has a
    // mutable reference to DT, so we can't use current node (which also has a mutable reference to
    // DT).
    pub fn delete_and_next_compatible(self, compatible: &CStr) -> Result<Option<Self>> {
        // SAFETY: Accesses (read-only) are constrained to the DT totalsize.
        let ret = unsafe {
            libfdt_bindgen::fdt_node_offset_by_compatible(
                self.fdt.as_ptr(),
                self.offset,
                compatible.as_ptr(),
            )
        };
        let next_offset = fdt_err_or_option(ret)?;

        self.delete_and_next(next_offset)
    }

    fn delete_and_next(mut self, next_offset: Option<c_int>) -> Result<Option<Self>> {
        if Some(self.offset) == next_offset {
            return Err(FdtError::Internal);
        }

        // SAFETY: nop_self() only touches bytes of the self and its properties and subnodes, and
        // doesn't alter any other blob in the tree. self.fdt and next_offset would remain valid.
        unsafe { self.nop_self()? };

        Ok(next_offset.map(|offset| Self { fdt: self.fdt, offset }))
    }

    /// Deletes this node effectively from DT, by setting it with FDT_NOP
    pub fn nop(mut self) -> Result<()> {
        // SAFETY: This consumes self, so invalid node wouldn't be used any further
        unsafe { self.nop_self() }
    }

    /// Deletes this node effectively from DT, by setting it with FDT_NOP.
    /// This only changes bytes of the node and its properties and subnodes, and doesn't alter or
    /// move any other part of the tree.
    /// SAFETY: This node is no longer valid.
    unsafe fn nop_self(&mut self) -> Result<()> {
        // SAFETY: Accesses are constrained to the DT totalsize (validated by ctor).
        let ret = unsafe { libfdt_bindgen::fdt_nop_node(self.fdt.as_mut_ptr(), self.offset) };

        fdt_err_expect_zero(ret)
    }
}

/// Wrapper around low-level libfdt functions.
#[derive(Debug)]
#[repr(transparent)]
pub struct Fdt {
    buffer: [u8],
}

impl Fdt {
    /// Wraps a slice containing a Flattened Device Tree.
    ///
    /// Fails if the FDT does not pass validation.
    pub fn from_slice(fdt: &[u8]) -> Result<&Self> {
        libfdt::check_full(fdt)?;
        // SAFETY: The FDT was validated.
        let fdt = unsafe { Self::unchecked_from_slice(fdt) };

        Ok(fdt)
    }

    /// Wraps a mutable slice containing a Flattened Device Tree.
    ///
    /// Fails if the FDT does not pass validation.
    pub fn from_mut_slice(fdt: &mut [u8]) -> Result<&mut Self> {
        libfdt::check_full(fdt)?;
        // SAFETY: The FDT was validated.
        let fdt = unsafe { Self::unchecked_from_mut_slice(fdt) };

        Ok(fdt)
    }

    /// Creates an empty Flattened Device Tree with a mutable slice.
    pub fn create_empty_tree(fdt: &mut [u8]) -> Result<&mut Self> {
        libfdt::create_empty_tree(fdt)?;

        Self::from_mut_slice(fdt)
    }

    /// Wraps a slice containing a Flattened Device Tree.
    ///
    /// # Safety
    ///
    /// It is undefined to call this function on a slice that does not contain a valid device tree.
    pub unsafe fn unchecked_from_slice(fdt: &[u8]) -> &Self {
        let self_ptr = fdt as *const _ as *const _;
        // SAFETY: The pointer is non-null, dereferenceable, and points to allocated memory.
        unsafe { &*self_ptr }
    }

    /// Wraps a mutable slice containing a Flattened Device Tree.
    ///
    /// # Safety
    ///
    /// It is undefined to call this function on a slice that does not contain a valid device tree.
    pub unsafe fn unchecked_from_mut_slice(fdt: &mut [u8]) -> &mut Self {
        let self_mut_ptr = fdt as *mut _ as *mut _;
        // SAFETY: The pointer is non-null, dereferenceable, and points to allocated memory.
        unsafe { &mut *self_mut_ptr }
    }

    /// Updates this FDT from another FDT.
    pub fn clone_from(&mut self, other: &Self) -> Result<()> {
        let new_len = other.buffer.len();
        if self.buffer.len() < new_len {
            return Err(FdtError::NoSpace);
        }

        let zeroed_len = self.totalsize().checked_sub(new_len);
        let (cloned, zeroed) = self.buffer.split_at_mut(new_len);

        cloned.clone_from_slice(&other.buffer);
        if let Some(len) = zeroed_len {
            zeroed[..len].fill(0);
        }

        Ok(())
    }

    /// Unpacks the DT to cover the whole slice it is contained in.
    pub fn unpack(&mut self) -> Result<()> {
        // SAFETY: "Opens" the DT in-place (supported use-case) by updating its header and
        // internal structures to make use of the whole self.fdt slice but performs no accesses
        // outside of it and leaves the DT in a state that will be detected by other functions.
        let ret = unsafe {
            libfdt_bindgen::fdt_open_into(
                self.as_ptr(),
                self.as_mut_ptr(),
                self.capacity().try_into().map_err(|_| FdtError::Internal)?,
            )
        };
        fdt_err_expect_zero(ret)
    }

    /// Packs the DT to take a minimum amount of memory.
    ///
    /// Doesn't shrink the underlying memory slice.
    pub fn pack(&mut self) -> Result<()> {
        // SAFETY: "Closes" the DT in-place by updating its header and relocating its structs.
        let ret = unsafe { libfdt_bindgen::fdt_pack(self.as_mut_ptr()) };
        fdt_err_expect_zero(ret)
    }

    /// Applies a DT overlay on the base DT.
    ///
    /// # Safety
    ///
    /// On failure, the library corrupts the DT and overlay so both must be discarded.
    pub unsafe fn apply_overlay<'a>(&'a mut self, overlay: &'a mut Fdt) -> Result<&'a mut Self> {
        let ret =
        // SAFETY: Both pointers are valid because they come from references, and fdt_overlay_apply
        // doesn't keep them after it returns. It may corrupt their contents if there is an error,
        // but that's our caller's responsibility.
            unsafe { libfdt_bindgen::fdt_overlay_apply(self.as_mut_ptr(), overlay.as_mut_ptr()) };
        fdt_err_expect_zero(ret)?;
        Ok(self)
    }

    /// Returns an iterator of memory banks specified the "/memory" node.
    /// Throws an error when the "/memory" is not found in the device tree.
    ///
    /// NOTE: This does not support individual "/memory@XXXX" banks.
    pub fn memory(&self) -> Result<MemRegIterator> {
        let node = self.node(cstr!("/memory"))?.ok_or(FdtError::NotFound)?;
        if node.device_type()? != Some(cstr!("memory")) {
            return Err(FdtError::BadValue);
        }
        node.reg()?.ok_or(FdtError::BadValue).map(MemRegIterator::new)
    }

    /// Returns the first memory range in the `/memory` node.
    pub fn first_memory_range(&self) -> Result<Range<usize>> {
        self.memory()?.next().ok_or(FdtError::NotFound)
    }

    /// Returns the standard /chosen node.
    pub fn chosen(&self) -> Result<Option<FdtNode>> {
        self.node(cstr!("/chosen"))
    }

    /// Returns the standard /chosen node as mutable.
    pub fn chosen_mut(&mut self) -> Result<Option<FdtNodeMut>> {
        self.node_mut(cstr!("/chosen"))
    }

    /// Returns the root node of the tree.
    pub fn root(&self) -> Result<FdtNode> {
        self.node(cstr!("/"))?.ok_or(FdtError::Internal)
    }

    /// Returns the standard /__symbols__ node.
    pub fn symbols(&self) -> Result<Option<FdtNode>> {
        self.node(cstr!("/__symbols__"))
    }

    /// Returns the standard /__symbols__ node as mutable
    pub fn symbols_mut(&mut self) -> Result<Option<FdtNodeMut>> {
        self.node_mut(cstr!("/__symbols__"))
    }

    /// Returns a tree node by its full path.
    pub fn node(&self, path: &CStr) -> Result<Option<FdtNode>> {
        let offset = self.path_offset(path.to_bytes())?;

        Ok(offset.map(|offset| FdtNode { fdt: self, offset }))
    }

    /// Iterate over nodes with a given compatible string.
    pub fn compatible_nodes<'a>(&'a self, compatible: &'a CStr) -> Result<CompatibleIterator<'a>> {
        CompatibleIterator::new(self, compatible)
    }

    /// Returns max phandle in the tree.
    pub fn max_phandle(&self) -> Result<Phandle> {
        let mut phandle: u32 = 0;
        // SAFETY: Accesses (read-only) are constrained to the DT totalsize.
        let ret = unsafe { libfdt_bindgen::fdt_find_max_phandle(self.as_ptr(), &mut phandle) };

        fdt_err_expect_zero(ret)?;
        phandle.try_into()
    }

    /// Returns a node with the phandle
    pub fn node_with_phandle(&self, phandle: Phandle) -> Result<Option<FdtNode>> {
        let offset = self.node_offset_with_phandle(phandle)?;
        Ok(offset.map(|offset| FdtNode { fdt: self, offset }))
    }

    /// Returns a mutable node with the phandle
    pub fn node_mut_with_phandle(&mut self, phandle: Phandle) -> Result<Option<FdtNodeMut>> {
        let offset = self.node_offset_with_phandle(phandle)?;
        Ok(offset.map(|offset| FdtNodeMut { fdt: self, offset }))
    }

    fn node_offset_with_phandle(&self, phandle: Phandle) -> Result<Option<c_int>> {
        // SAFETY: Accesses are constrained to the DT totalsize.
        let ret = unsafe { libfdt_bindgen::fdt_node_offset_by_phandle(self.as_ptr(), phandle.0) };
        fdt_err_or_option(ret)
    }

    /// Returns the mutable root node of the tree.
    pub fn root_mut(&mut self) -> Result<FdtNodeMut> {
        self.node_mut(cstr!("/"))?.ok_or(FdtError::Internal)
    }

    /// Returns a mutable tree node by its full path.
    pub fn node_mut(&mut self, path: &CStr) -> Result<Option<FdtNodeMut>> {
        let offset = self.path_offset(path.to_bytes())?;

        Ok(offset.map(|offset| FdtNodeMut { fdt: self, offset }))
    }

    /// Returns the device tree as a slice (may be smaller than the containing buffer).
    pub fn as_slice(&self) -> &[u8] {
        &self.buffer[..self.totalsize()]
    }

    fn path_offset(&self, path: &[u8]) -> Result<Option<c_int>> {
        let len = path.len().try_into().map_err(|_| FdtError::BadPath)?;
        // SAFETY: Accesses are constrained to the DT totalsize (validated by ctor) and the
        // function respects the passed number of characters.
        let ret = unsafe {
            // *_namelen functions don't include the trailing nul terminator in 'len'.
            libfdt_bindgen::fdt_path_offset_namelen(self.as_ptr(), path.as_ptr().cast::<_>(), len)
        };

        fdt_err_or_option(ret)
    }

    fn get_from_ptr(&self, ptr: *const c_void, len: usize) -> Result<&[u8]> {
        let ptr = ptr as usize;
        let offset = ptr.checked_sub(self.as_ptr() as usize).ok_or(FdtError::Internal)?;
        self.buffer.get(offset..(offset + len)).ok_or(FdtError::Internal)
    }

    fn string(&self, offset: c_int) -> Result<&CStr> {
        // SAFETY: Accesses (read-only) are constrained to the DT totalsize.
        let res = unsafe { libfdt_bindgen::fdt_string(self.as_ptr(), offset) };
        if res.is_null() {
            return Err(FdtError::Internal);
        }

        // SAFETY: Non-null return from fdt_string() is valid null-terminating string within FDT.
        Ok(unsafe { CStr::from_ptr(res) })
    }

    /// Returns a shared pointer to the device tree.
    pub fn as_ptr(&self) -> *const c_void {
        self.buffer.as_ptr().cast()
    }

    fn as_mut_ptr(&mut self) -> *mut c_void {
        self.buffer.as_mut_ptr().cast::<_>()
    }

    fn capacity(&self) -> usize {
        self.buffer.len()
    }

    fn header(&self) -> &libfdt_bindgen::fdt_header {
        let p = self.as_ptr().cast();
        // SAFETY: A valid FDT (verified by constructor) must contain a valid fdt_header.
        unsafe { &*p }
    }

    fn totalsize(&self) -> usize {
        u32::from_be(self.header().totalsize) as usize
    }
}
