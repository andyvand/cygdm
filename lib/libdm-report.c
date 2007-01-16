/*
 * Copyright (C) 2002-2004 Sistina Software, Inc. All rights reserved.
 * Copyright (C) 2004 Red Hat, Inc. All rights reserved.
 *
 * This file is part of device-mapper userspace tools.
 * The code is based on LVM2 report function.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v.2.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "libdevmapper.h"
#include "list.h"
#include "log.h"

/*
 * Internal flags
 */
#define RH_SORT_REQUIRED	0x00000100
#define RH_HEADINGS_PRINTED	0x00000200

struct dm_report {
	struct dm_pool *mem;

	uint32_t report_types;
	const char *field_prefix;
	uint32_t flags;
	const char *separator;

	uint32_t keys_count;

	/* Ordered list of fields needed for this report */
	struct list field_props;

	/* Rows of report data */
	struct list rows;

	/* Array of field definitions */
	const struct dm_report_field_type *fields;
	const struct dm_report_object_type *types;

	/* To store caller private data */
	void *private;
};

/*
 * Internal per-field flags
 */
#define FLD_HIDDEN	0x00000100
#define FLD_SORT_KEY	0x00000200
#define FLD_ASCENDING	0x00000400
#define FLD_DESCENDING	0x00000800

struct field_properties {
	struct list list;
	uint32_t field_num;
	uint32_t sort_posn;
	unsigned width;
	const struct dm_report_object_type *type;
	uint32_t flags;
};

/*
 * Report data field
 */
struct dm_report_field {
	struct list list;
	struct field_properties *props;

	const char *report_string;	/* Formatted ready for display */
	const void *sort_value;		/* Raw value for sorting */
};

struct row {
	struct list list;
	struct dm_report *rh;
	struct list fields;			  /* Fields in display order */
	struct dm_report_field *(*sort_fields)[]; /* Fields in sort order */
};

static const struct dm_report_object_type *_find_type(struct dm_report *rh,
						      uint32_t report_type)
{
	const struct dm_report_object_type *t;

	for (t = rh->types; t->data_fn; t++)
		if (t->id == report_type)
			return t;

	return NULL;
}

/*
 * Data-munging functions to prepare each data type for display and sorting
 */

int dm_report_field_string(struct dm_report *rh, struct dm_pool *mem,
			   struct dm_report_field *field, const void *data)
{
	char *repstr;

	if (!(repstr = dm_pool_strdup(rh->mem, *(const char **) data))) {
		log_error("dm_report_field_string: dm_pool_strdup failed");
		return 0;
	}

	field->report_string = repstr;
	field->sort_value = (const void *) field->report_string;

	return 1;
}

int dm_report_field_int(struct dm_report *rh, struct dm_pool *mem,
			struct dm_report_field *field, const void *data)
{
	const int value = *(const int *) data;
	uint64_t *sortval;
	char *repstr;

	if (!(repstr = dm_pool_zalloc(rh->mem, 13))) {
		log_error("dm_report_field_int: dm_pool_alloc failed");
		return 0;
	}

	if (!(sortval = dm_pool_alloc(rh->mem, sizeof(int64_t)))) {
		log_error("dm_report_field_int: dm_pool_alloc failed");
		return 0;
	}

	if (dm_snprintf(repstr, 12, "%d", value) < 0) {
		log_error("dm_report_field_int: int too big: %d", value);
		return 0;
	}

	*sortval = (const uint64_t) value;
	field->sort_value = sortval;
	field->report_string = repstr;

	return 1;
}

int dm_report_field_uint32(struct dm_report *rh, struct dm_pool *mem,
			   struct dm_report_field *field, const void *data)
{
	const uint32_t value = *(const uint32_t *) data;
	uint64_t *sortval;
	char *repstr;

	if (!(repstr = dm_pool_zalloc(rh->mem, 12))) {
		log_error("dm_report_field_uint32: dm_pool_alloc failed");
		return 0;
	}

	if (!(sortval = dm_pool_alloc(rh->mem, sizeof(uint64_t)))) {
		log_error("dm_report_field_uint32: dm_pool_alloc failed");
		return 0;
	}

	if (dm_snprintf(repstr, 11, "%u", value) < 0) {
		log_error("dm_report_field_uint32: uint32 too big: %u", value);
		return 0;
	}

	*sortval = (const uint64_t) value;
	field->sort_value = sortval;
	field->report_string = repstr;

	return 1;
}

int dm_report_field_int32(struct dm_report *rh, struct dm_pool *mem,
			  struct dm_report_field *field, const void *data)
{
	const int32_t value = *(const int32_t *) data;
	uint64_t *sortval;
	char *repstr;

	if (!(repstr = dm_pool_zalloc(rh->mem, 13))) {
		log_error("dm_report_field_int32: dm_pool_alloc failed");
		return 0;
	}

	if (!(sortval = dm_pool_alloc(rh->mem, sizeof(int64_t)))) {
		log_error("dm_report_field_int32: dm_pool_alloc failed");
		return 0;
	}

	if (dm_snprintf(repstr, 12, "%d", value) < 0) {
		log_error("dm_report_field_int32: int32 too big: %d", value);
		return 0;
	}

	*sortval = (const uint64_t) value;
	field->sort_value = sortval;
	field->report_string = repstr;

	return 1;
}

int dm_report_field_uint64(struct dm_report *rh, struct dm_pool *mem,
			   struct dm_report_field *field, const void *data)
{
	const int value = *(const uint64_t *) data;
	uint64_t *sortval;
	char *repstr;

	if (!(repstr = dm_pool_zalloc(rh->mem, 22))) {
		log_error("dm_report_field_uint64: dm_pool_alloc failed");
		return 0;
	}

	if (!(sortval = dm_pool_alloc(rh->mem, sizeof(uint64_t)))) {
		log_error("dm_report_field_uint64: dm_pool_alloc failed");
		return 0;
	}

	if (dm_snprintf(repstr, 21, "%d", value) < 0) {
		log_error("dm_report_field_uint64: uint64 too big: %d", value);
		return 0;
	}

	*sortval = (const uint64_t) value;
	field->sort_value = sortval;
	field->report_string = repstr;

	return 1;
}

/*
 * Helper functions for custom report functions
 */
void dm_report_field_set_value(struct dm_report_field *field, const void *value, const void *sortvalue)
{
	field->report_string = (const char *) value;
	field->sort_value = sortvalue ? : value;
}

/*
 * show help message
 */
static void _display_fields(struct dm_report *rh)
{
	uint32_t f;
	const struct dm_report_object_type *type;
	const char *desc, *last_desc = "";

	for (f = 0; rh->fields[f].report_fn; f++) {
		if ((type = _find_type(rh, rh->fields[f].type)) && type->desc)
			desc = type->desc;
		else
			desc = " ";
		if (desc != last_desc) {
			if (*last_desc)
				log_print(" ");
			log_print("%s Fields", desc);
		}

		log_print("- %s", rh->fields[f].id);
		last_desc = desc;
	}
}

/*
 * Initialise report handle
 */
static int _copy_field(struct dm_report *rh, struct field_properties *dest,
		       uint32_t field_num)
{
	dest->field_num = field_num;
	dest->width = rh->fields[field_num].width;
	dest->flags = rh->fields[field_num].flags & DM_REPORT_FIELD_MASK;

	/* set object type method */
	dest->type = _find_type(rh, rh->fields[field_num].type);
	if (!dest->type) {
		log_error("dm_report: field not match: %s",
			  rh->fields[field_num].id);
		return 0;
	}

	return 1;
}

static int _field_match(struct dm_report *rh, const char *field, size_t flen)
{
	uint32_t f, l;
	struct field_properties *fp;

	if (!flen)
		return 0;

	for (f = 0; rh->fields[f].report_fn; f++) {
		if ((!strncasecmp(rh->fields[f].id, field, flen) &&
		     strlen(rh->fields[f].id) == flen) ||
		    (l = strlen(rh->field_prefix),
		     !strncasecmp(rh->field_prefix, rh->fields[f].id, l) &&
		     !strncasecmp(rh->fields[f].id + l, field, flen) &&
		     strlen(rh->fields[f].id) == l + flen)) {
			rh->report_types |= rh->fields[f].type;
			if (!(fp = dm_pool_zalloc(rh->mem, sizeof(*fp)))) {
				log_error("dm_report: "
					  "struct field_properties allocation "
					  "failed");
				return 0;
			}
			if (!_copy_field(rh, fp, f))
				return 0;

			list_add(&rh->field_props, &fp->list);
			return 1;
		}
	}

	return 0;
}

static int _add_sort_key(struct dm_report *rh, uint32_t field_num,
			 uint32_t flags)
{
	struct field_properties *fp, *found = NULL;

	list_iterate_items(fp, &rh->field_props) {
		if (fp->field_num == field_num) {
			found = fp;
			break;
		}
	}

	if (!found) {
		rh->report_types |= rh->fields[field_num].type;
		if (!(found = dm_pool_zalloc(rh->mem, sizeof(*found)))) {
			log_error("dm_report: "
				  "struct field_properties allocation failed");
			return 0;
		}
		if (!_copy_field(rh, found, field_num))
			return 0;

		/* Add as a non-display field */
		found->flags |= FLD_HIDDEN;

		list_add(&rh->field_props, &found->list);
	}

	if (found->flags & FLD_SORT_KEY) {
		log_error("dm_report: Ignoring duplicate sort field: %s",
			  rh->fields[field_num].id);
		return 1;
	}

	found->flags |= FLD_SORT_KEY;
	found->sort_posn = rh->keys_count++;
	found->flags |= flags;

	return 1;
}

static int _key_match(struct dm_report *rh, const char *key, size_t len)
{
	uint32_t f, l;
	uint32_t flags;

	if (!len)
		return 0;

	if (*key == '+') {
		key++;
		len--;
		flags = FLD_ASCENDING;
	} else if (*key == '-') {
		key++;
		len--;
		flags = FLD_DESCENDING;
	} else
		flags = FLD_ASCENDING;

	if (!len) {
		log_error("dm_report: Missing sort field name");
		return 0;
	}

	for (f = 0; rh->fields[f].report_fn; f++) {
		if ((!strncasecmp(rh->fields[f].id, key, len) &&
		     strlen(rh->fields[f].id) == len) ||
		    (l = strlen(rh->field_prefix),
		     !strncasecmp(rh->field_prefix, rh->fields[f].id, l) &&
		     !strncasecmp(rh->fields[f].id + l, key, len) &&
		     strlen(rh->fields[f].id) == l + len)) {
			return _add_sort_key(rh, f, flags);
		}
	}

	return 0;
}

static int _parse_options(struct dm_report *rh, const char *format)
{
	const char *ws;		/* Word start */
	const char *we = format;	/* Word end */

	while (*we) {
		/* Allow consecutive commas */
		while (*we && *we == ',')
			we++;

		/* start of the field name */
		ws = we;
		while (*we && *we != ',')
			we++;

		if (!_field_match(rh, ws, (size_t) (we - ws))) {
			_display_fields(rh);
			log_print(" ");
			log_error("dm_report: Unrecognised field: %.*s",
				  (int) (we - ws), ws);
			return 0;
		}
	}

	return 1;
}

static int _parse_keys(struct dm_report *rh, const char *keys)
{
	const char *ws;		/* Word start */
	const char *we = keys;	/* Word end */

	while (*we) {
		/* Allow consecutive commas */
		while (*we && *we == ',')
			we++;
		ws = we;
		while (*we && *we != ',')
			we++;
		if (!_key_match(rh, ws, (size_t) (we - ws))) {
			log_error("dm_report: Unrecognised field: %.*s",
				  (int) (we - ws), ws);
			return 0;
		}
	}

	return 1;
}

struct dm_report *dm_report_init(uint32_t *report_types,
				 const struct dm_report_object_type *types,
				 const struct dm_report_field_type *fields,
				 const char *output_fields,
				 const char *output_separator,
				 uint32_t output_flags,
				 const char *sort_keys,
				 void *private)
{
	struct dm_report *rh;
	const struct dm_report_object_type *type;

	if (!(rh = dm_malloc(sizeof(*rh)))) {
		log_error("dm_report_init: dm_malloc failed");
		return 0;
	}
	memset(rh, 0, sizeof(*rh));

	/*
	 * rh->report_types is updated in _parse_options() and _parse_keys()
	 * to contain all types corresponding to the fields specified by
	 * options or keys.
	 */
	if (report_types)
		rh->report_types = *report_types;

	rh->separator = output_separator;
	rh->fields = fields;
	rh->types = types;
	rh->private = private;

	rh->flags |= output_flags & DM_REPORT_OUTPUT_MASK;

	if (output_flags & DM_REPORT_OUTPUT_BUFFERED)
		rh->flags |= RH_SORT_REQUIRED;

	list_init(&rh->field_props);
	list_init(&rh->rows);

	if ((type = _find_type(rh, rh->report_types)) && type->prefix)
		rh->field_prefix = type->prefix;
	else
		rh->field_prefix = "";

	if (!(rh->mem = dm_pool_create("report", 10 * 1024))) {
		log_error("dm_report_init: allocation of memory pool failed");
		return NULL;
	}

	/* Generate list of fields for output based on format string & flags */
	if (!_parse_options(rh, output_fields))
		return NULL;

	if (!_parse_keys(rh, sort_keys))
		return NULL;

	/* Return updated types value for further compatility check by caller */
	if (report_types)
		*report_types = rh->report_types;

	return rh;
}

void dm_report_free(struct dm_report *rh)
{
	dm_pool_destroy(rh->mem);
	dm_free(rh);
}

/*
 * Create a row of data for an object
 */
static void * _report_get_field_data(struct dm_report *rh,
			      struct field_properties *fp, void *object)
{
	void *ret = fp->type->data_fn(object);

	if (!ret)
		return NULL;

	return ret + rh->fields[fp->field_num].offset;
}

int dm_report_object(struct dm_report *rh, void *object)
{
	struct field_properties *fp;
	struct row *row;
	struct dm_report_field *field;
	void *data = NULL;

	if (!(row = dm_pool_zalloc(rh->mem, sizeof(*row)))) {
		log_error("dm_report_object: struct row allocation failed");
		return 0;
	}

	row->rh = rh;

	if ((rh->flags & RH_SORT_REQUIRED) &&
	    !(row->sort_fields =
		dm_pool_zalloc(rh->mem, sizeof(struct dm_report_field *) *
			       rh->keys_count))) {
		log_error("dm_report_object: "
			  "row sort value structure allocation failed");
		return 0;
	}

	list_init(&row->fields);
	list_add(&rh->rows, &row->list);

	/* For each field to be displayed, call its report_fn */
	list_iterate_items(fp, &rh->field_props) {
		if (!(field = dm_pool_zalloc(rh->mem, sizeof(*field)))) {
			log_error("dm_report_object: "
				  "struct dm_report_field allocation failed");
			return 0;
		}
		field->props = fp;

		data = _report_get_field_data(rh, fp, object);
		if (!data)
			return 0;

		if (!rh->fields[fp->field_num].report_fn(rh, rh->mem,
							 field, data,
							 rh->private)) {
			log_error("dm_report_object: "
				  "report function failed for field %s",
				  rh->fields[fp->field_num].id);
			return 0;
		}

		if ((strlen(field->report_string) > field->props->width))
			field->props->width = strlen(field->report_string);

		if ((rh->flags & RH_SORT_REQUIRED) &&
		    (field->props->flags & FLD_SORT_KEY)) {
			(*row->sort_fields)[field->props->sort_posn] = field;
		}
		list_add(&row->fields, &field->list);
	}

	if (!(rh->flags & DM_REPORT_OUTPUT_BUFFERED))
		return dm_report_output(rh);

	return 1;
}

/*
 * Print row of headings
 */
static int _report_headings(struct dm_report *rh)
{
	struct field_properties *fp;
	const char *heading;
	char buf[1024];

	if (rh->flags & RH_HEADINGS_PRINTED)
		return 1;

	rh->flags |= RH_HEADINGS_PRINTED;

	if (!(rh->flags & DM_REPORT_OUTPUT_HEADINGS))
		return 1;

	if (!dm_pool_begin_object(rh->mem, 128)) {
		log_error("dm_report: "
			  "dm_pool_begin_object failed for headings");
		return 0;
	}

	/* First heading line */
	list_iterate_items(fp, &rh->field_props) {
		if (fp->flags & FLD_HIDDEN)
			continue;

		heading = rh->fields[fp->field_num].heading;
		if (rh->flags & DM_REPORT_OUTPUT_ALIGNED) {
			if (dm_snprintf(buf, sizeof(buf), "%-*.*s",
					 fp->width, fp->width, heading) < 0) {
				log_error("dm_report: snprintf heading failed");
				goto bad;
			}
			if (!dm_pool_grow_object(rh->mem, buf, fp->width)) {
				log_error("dm_report: Failed to generate report headings for printing");
				goto bad;
			}
		} else if (!dm_pool_grow_object(rh->mem, heading,
						strlen(heading))) {
			log_error("dm_report: Failed to generate report headings for printing");
			goto bad;
		}

		if (!list_end(&rh->field_props, &fp->list))
			if (!dm_pool_grow_object(rh->mem, rh->separator,
					      strlen(rh->separator))) {
				log_error("dm_report: Failed to generate report headings for printing");
				goto bad;
			}
	}
	if (!dm_pool_grow_object(rh->mem, "\0", 1)) {
		log_error("dm_report: Failed to generate report headings for printing");
		goto bad;
	}
	log_print("%s", (char *) dm_pool_end_object(rh->mem));

	return 1;

      bad:
	dm_pool_abandon_object(rh->mem);
	return 0;
}

/*
 * Sort rows of data
 */
static int _row_compare(const void *a, const void *b)
{
	const struct row *rowa = *(const struct row **) a;
	const struct row *rowb = *(const struct row **) b;
	const struct dm_report_field *sfa, *sfb;
	uint32_t cnt;

	for (cnt = 0; cnt < rowa->rh->keys_count; cnt++) {
		sfa = (*rowa->sort_fields)[cnt];
		sfb = (*rowb->sort_fields)[cnt];
		if (sfa->props->flags & DM_REPORT_FIELD_NUMBER) {
			const uint64_t numa =
			    *(const uint64_t *) sfa->sort_value;
			const uint64_t numb =
			    *(const uint64_t *) sfb->sort_value;

			if (numa == numb)
				continue;

			if (sfa->props->flags & FLD_ASCENDING) {
				return (numa > numb) ? 1 : -1;
			} else {	/* FLD_DESCENDING */
				return (numa < numb) ? 1 : -1;
			}
		} else {	/* DM_REPORT_FIELD_STRING */
			const char *stra = (const char *) sfa->sort_value;
			const char *strb = (const char *) sfb->sort_value;
			int cmp = strcmp(stra, strb);

			if (!cmp)
				continue;

			if (sfa->props->flags & FLD_ASCENDING) {
				return (cmp > 0) ? 1 : -1;
			} else {	/* FLD_DESCENDING */
				return (cmp < 0) ? 1 : -1;
			}
		}
	}

	return 0;		/* Identical */
}

static int _sort_rows(struct dm_report *rh)
{
	struct row *(*rows)[];
	uint32_t count = 0;
	struct row *row;

	if (!(rows = dm_pool_alloc(rh->mem, sizeof(**rows) *
				list_size(&rh->rows)))) {
		log_error("dm_report: sort array allocation failed");
		return 0;
	}

	list_iterate_items(row, &rh->rows)
		(*rows)[count++] = row;

	qsort(rows, count, sizeof(**rows), _row_compare);

	list_init(&rh->rows);
	while (count--)
		list_add_h(&rh->rows, &(*rows)[count]->list);

	return 1;
}

/*
 * Produce report output
 */
int dm_report_output(struct dm_report *rh)
{
	struct list *fh, *rowh, *ftmp, *rtmp;
	struct row *row = NULL;
	struct dm_report_field *field;
	const char *repstr;
	char buf[4096];
	unsigned width;

	if (list_empty(&rh->rows))
		return 1;

	/* Sort rows */
	if ((rh->flags & RH_SORT_REQUIRED))
		_sort_rows(rh);

	/* If headings not printed yet, calculate field widths and print them */
	if (!(rh->flags & RH_HEADINGS_PRINTED))
		_report_headings(rh);

	/* Print and clear buffer */
	list_iterate_safe(rowh, rtmp, &rh->rows) {
		if (!dm_pool_begin_object(rh->mem, 512)) {
			log_error("dm_report: "
				  "dm_pool_begin_object failed for row");
			return 0;
		}
		row = list_item(rowh, struct row);
		list_iterate_safe(fh, ftmp, &row->fields) {
			field = list_item(fh, struct dm_report_field);
			if (field->props->flags & FLD_HIDDEN)
				continue;

			repstr = field->report_string;
			width = field->props->width;
			if (!(rh->flags & DM_REPORT_OUTPUT_ALIGNED)) {
				if (!dm_pool_grow_object(rh->mem, repstr,
						      strlen(repstr)))
					goto bad_grow;
			} else if (field->props->flags & DM_REPORT_FIELD_ALIGN_LEFT) {
				if (dm_snprintf(buf, sizeof(buf), "%-*.*s",
						 width, width, repstr) < 0)
					goto bad_snprintf;
				if (!dm_pool_grow_object(rh->mem, buf, width))
					goto bad_grow;
			} else if (field->props->flags & DM_REPORT_FIELD_ALIGN_RIGHT) {
				if (dm_snprintf(buf, sizeof(buf), "%*.*s",
						 width, width, repstr) < 0)
					goto bad_snprintf;
				if (!dm_pool_grow_object(rh->mem, buf, width))
					goto bad_grow;
			}

			if (!list_end(&row->fields, fh))
				if (!dm_pool_grow_object(rh->mem, rh->separator,
						      strlen(rh->separator)))
					goto bad_grow;
			list_del(&field->list);
		}
		if (!dm_pool_grow_object(rh->mem, "\0", 1))
			goto bad_grow;
		log_print("%s", (char *) dm_pool_end_object(rh->mem));
		list_del(&row->list);
	}

	if (row)
		dm_pool_free(rh->mem, row);

	return 1;

      bad_snprintf:
	log_error("dm_report: snprintf row failed");
      bad_grow:
	log_error("dm_report: Failed to generate row for printing");
	dm_pool_abandon_object(rh->mem);
	return 0;
}